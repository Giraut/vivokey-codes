#!/usr/bin/python3
"""
GTK authenticator to read TOTP codes from a Vivokey OTP applet, display them
and copy them into the clipboard.

This program starts minimized in the system tray. Click on the icon then select
"Get codes", or middle-click on the icon, to start the authenticator's panel.

As soon as the panel comes up, it starts polling the PC/SC reader whose name is
specified in the Reader field for a Vivokey token to read. When the panel is
closed, it stops polling the reader.

Present your Vivokey token to the reader. If the token is passworded, you can
set the password in the panel.

If a token is read successfully, the accounts and associated TOTP codes it
returned are displayed in the list. Select one entry to copy the code into the
clipboard. The code may be pasted into any application with right-click-paste,
Ctrl-V or with the middle-click.

This program uses the Vivokey Manager utility. See:

https://github.com/Giraut/vivokey-manager
"""

### Parameters
default_vkman = "/usr/bin/vkman"
default_reader = "0"
config_file = "~/.vivokey_codes.cfg"

auto_close_idle_window_timeout = 120 #s
auto_close_idle_window_countdown = 30 #s

title = "Vivokey Codes"
icon = "vivokey_codes"
min_visible_list_lines = 10

tray_item_id = "vivokey_codes"

sample_issuer_string = "Acme, Inc. (International Foobar Division)"
sample_account_string = "oleg.mcnoleg@acme-incorporated-international.com"
sample_code_string = "0123456789"



### Modules
import re
import os
import sys
import argparse
from time import time
from subprocess import Popen, PIPE

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

gi.require_version("AppIndicator3", "0.1")
from gi.repository import AppIndicator3



### Classes
class tray_item():
  """Authenticator tray item
  """

  def __init__(self, vkman):
    """__init__ method
    """

    self.vkman = vkman
    self.cfgfile = os.path.expanduser(config_file)

    # Start the authenticator in deactivated mode
    self.auth = authenticator(self.vkman, self.cfgfile)

    # Create the app indicator
    self.ind = AppIndicator3.Indicator.new(tray_item_id, icon,
						AppIndicator3.IndicatorCategory.
						APPLICATION_STATUS)
    self.ind.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
    self.ind.set_title(title)

    # Create and set the app indicator's menu
    self.menu = Gtk.Menu()

    self.activate_authenticator = Gtk.MenuItem(label = 'Get codes')
    self.activate_authenticator.connect('activate', self.auth.activate)
    self.menu.append(self.activate_authenticator)

    self.separator = Gtk.SeparatorMenuItem()
    self.menu.append(self.separator)

    self.exit = Gtk.MenuItem(label = 'Exit')
    self.exit.connect('activate', Gtk.main_quit)
    self.menu.append(self.exit)

    self.ind.set_menu(self.menu)

    # Set the app indicator's secondary target (i.e. middle-click)
    self.ind.set_secondary_activate_target(self.activate_authenticator)

    # Show the app indicator's menu
    self.menu.show_all()

    # Run the app
    Gtk.main()



class authenticator(Gtk.Window):
  """Main authenticator application
  """

  def __init__(self, vkman, cfgfile):
    """__init__ method
    """

    super().__init__(title = title)

    self.activated = False

    self.vkman = vkman
    self.cfgfile = cfgfile

    # Get the clipboards: selection clipboard for regular copy/paste and primary
    # clipboard for GNOME-style middle-click paste
    self.selection_clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    self.selprimary_clipboard = Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY)

    self.vkman_proc = None

    # Try to read the configuration file, fail silently
    self.reader = None
    self.oath_pwd = None
    self.oath_pwd_remember = False

    try:
      with open(self.cfgfile, "r") as f:

        params = f.read().splitlines()

        if len(params) == 3 and params[2] in ("Remember", "Forget"):
          self.reader, self.oath_pwd, self.oath_pwd_remember = params
          self.oath_pwd_remember = oath_pwd_remember == "Remember"

    except:
      pass

    self.current_filter = ""
    self.statusbar_messages = [None] * 3

    self.stop_timeout_func = False

    self.last_scan_was_error = False

    # Set the authenticator's icon. Soft-fail as lack of icon is only cosmetic
    try:
      self.set_icon(Gtk.IconTheme.get_default().load_icon(icon, 64, 0))

    except Exception as e:
      print("WARNING: error loading icon {}: {}!".format(icon, e),
		file = sys.stderr)

    # Set the window's border width
    self.set_border_width(10)

    # Create the liststore model for the list of accounts / codes
    self.liststore = Gtk.ListStore(str, str, str)

    # Create the filter, feeding it with the liststore model
    self.filter = self.liststore.filter_new()

    # Set the filter function
    self.filter.set_visible_func(self.filter_func)

    # Create the treeview, making it use the filter as a model, and add the
    # columns
    self.treeview = Gtk.TreeView(model = self.filter)
    self.treeview_select = self.treeview.get_selection()
    self.treeview_select.connect("changed", self.on_treeview_selection)
    self.treeview.connect("button_press_event", self.on_clicked)

    # Get and set the text renderer
    renderer = Gtk.CellRendererText()
    renderer.set_fixed_height_from_font(1)

    # Calculate the size in pixels of a typical issuer, account and code
    text_widths = [0, 0, 0]
    for i, s in enumerate([sample_issuer_string,
				sample_account_string,
				sample_code_string]):
      pango = self.treeview.create_pango_layout(s)
      text_widths[i], text_height = pango.get_pixel_size()

    for i, column_title in enumerate(["Issuer", "Account", "Code"]):
      column = Gtk.TreeViewColumn(column_title, renderer, text = i)
      column.set_min_width(text_widths[i])
      column.set_expand(True)
      self.treeview.append_column(column)

    # Create the text entry for the reader, with a label
    self.reader_entry_label = Gtk.Label(label = "PC/SC Reader:")

    self.reader_entry = Gtk.Entry()
    self.reader_entry.set_placeholder_text(default_reader)
    if self.reader:
      self.reader_entry.set_text(self.reader)
    self.reader_entry.connect("activate", self.on_cfg_entry_update)
    self.reader_entry.connect("changed", self.on_cfg_entry_update)
    self.reader_entry.connect("button_press_event", self.on_clicked)

    self.reader_entry_row = Gtk.HBox()

    self.reader_entry_row.pack_start(self.reader_entry_label,
						expand = False, fill = False,
						padding = 1)

    self.reader_entry_row.pack_end(self.reader_entry,
						expand = True, fill = True,
						padding = 1)

    # Create the text entry for the OATH password, with a label and a "remember"
    # check button
    self.oath_pwd_entry_label = Gtk.Label(label = "Vivokey password:")

    self.oath_pwd_entry = Gtk.Entry()
    self.oath_pwd_entry.set_placeholder_text("None")
    if self.oath_pwd:
      self.oath_pwd_entry.set_text(self.oath_pwd)
    self.oath_pwd_entry.set_visibility(False)
    self.oath_pwd_entry.connect("activate", self.on_cfg_entry_update)
    self.oath_pwd_entry.connect("changed", self.on_cfg_entry_update)
    self.oath_pwd_entry.connect("button_press_event", self.on_clicked)

    self.oath_pwd_entry_checkbtn = Gtk.CheckButton(label = "remember")
    self.oath_pwd_entry_checkbtn.set_active(self.oath_pwd_remember)
    self.oath_pwd_entry_checkbtn.connect("toggled", self.on_cfg_entry_update)

    self.oath_pwd_entry_row = Gtk.HBox()

    self.oath_pwd_entry_row.pack_start(self.oath_pwd_entry_label,
						expand = False, fill = False,
						padding = 1)

    self.oath_pwd_entry_row.pack_start(self.oath_pwd_entry,
						expand = True, fill = True,
						padding = 1)

    self.oath_pwd_entry_row.pack_end(self.oath_pwd_entry_checkbtn,
						expand = False, fill = False,
						padding = 1)

    # Put the treeview in a scrolled window
    self.scrollable_treelist = Gtk.ScrolledWindow()
    self.scrollable_treelist.set_hexpand(True)
    self.scrollable_treelist.set_vexpand(True)
    self.scrollable_treelist.set_min_content_width(sum(text_widths))
    self.scrollable_treelist.set_min_content_height(1.5 * text_height * \
							min_visible_list_lines)
    self.scrollable_treelist.add(self.treeview)

    # Create the text entry for the filter string, with a label
    self.filter_entry = Gtk.Entry()
    self.filter_entry.set_placeholder_text("None")
    self.filter_entry.connect("activate", self.on_filter_entry_update)
    self.filter_entry.connect("changed", self.on_filter_entry_update)
    self.filter_entry.connect("button_press_event", self.on_clicked)

    self.filter_entry_label = Gtk.Label(label = "Filter:")

    self.filter_entry_row = Gtk.HBox()

    self.filter_entry_row.pack_start(self.filter_entry_label,
						expand = False, fill = True,
						padding = 1)
    self.filter_entry_row.pack_end(self.filter_entry,
						expand = True, fill = True,
						padding = 1)

    # Create the status bar, with a spinner to suggest we're doing some work
    self.statusbar = Gtk.Statusbar()

    self.spinner = Gtk.Spinner()

    self.statusbar_row = Gtk.HBox()

    self.statusbar_row.pack_start(self.statusbar,
					expand = True, fill = True,
					padding = 1)

    self.statusbar_row.pack_end(self.spinner,
					expand = False, fill = True,
					padding = 1)

    self.statusbar_with_labeled_frame = Gtk.Frame(label = "Status")
    self.statusbar_with_labeled_frame.add(self.statusbar_row)

    # Put everything together in a grid
    self.grid = Gtk.Grid()
    self.add(self.grid)

    self.grid.attach(self.reader_entry_row, 0, 0, 1, 10)

    self.grid.attach_next_to(self.oath_pwd_entry_row,
				self.reader_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.grid.attach_next_to(self.scrollable_treelist,
				self.oath_pwd_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.grid.attach_next_to(self.filter_entry_row,
				self.scrollable_treelist,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.grid.attach_next_to(self.statusbar_with_labeled_frame,
				self.filter_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    # Focus on the filter entry by default
    self.filter_entry.grab_focus()

    # Also catch clicks inside the window, outside of the above widgets
    self.add_events(Gdk.EventMask.BUTTON_PRESS_MASK)
    self.connect("button-press-event", self.on_clicked)

    # Refresh the auto-close timestamp for the first time
    self.refresh_autoclose_tstamp()

    # Catch the user closing the window so we can deactivate instead of quitting
    self.connect("delete-event", self.deactivate)



  def activate(self, _):
    """Activate the authenticator - i.e. unhide the window and start the
    periodic timeout function that does the scanning
    """

    # If we're already activated, we have nothing to do
    if self.activated:
      return

    self.activated = True

    self.refresh_autoclose_tstamp()

    # Clear the liststore and the status bar, so the user is presented with a
    # fresh screen
    self.liststore.clear()
    for i in range(len(self.statusbar_messages)):
      self.set_statusbar(i, None)

    # Start the periodic timeout function and make it run every .2 second
    self.stop_timeout_func = False
    GLib.timeout_add(200, self.timeout_func)

    # Ask the window manager to keep it above all the other windows until we
    # regain focus
    self.set_keep_above(True)
    self.window_kept_above = True

    # Start the spinner
    self.spinner.start()

    # Show the window
    self.show_all()



  def filter_func(self, tree_model, i, data):
    """Tests if the issuer or the account in the row contain the filter text
    """

    return not self.current_filter or \
	re.search(self.current_filter, tree_model[i][0], re.I) is not None or \
	re.search(self.current_filter, tree_model[i][1], re.I) is not None



  def set_statusbar(self, lvl, msg):
    """Set a message for the status bar at a certain importance level.
    The status bar displays the message with the highest importance.
    Returns whether the message at that importance level was changed.
    """

    # Get the message currently displayed by the status bar
    c = ([None] + [c for c in self.statusbar_messages if c is not None])[-1]

    # Update the message at that importance level
    msg_at_lvl_changed = self.statusbar_messages[lvl] != msg
    self.statusbar_messages[lvl] = msg

    # Get the new message that should be displayed by the status bar
    n = ([None] + [c for c in self.statusbar_messages if c is not None])[-1]

    # Clear the status bar if it already shows something and it should change
    if c and (not n or n != c):
      self.statusbar.pop(0)

    # Set the new message in the status bar if it's not empty and it's
    # different from what's already displayed
    if n and n != c:
      self.statusbar.push(0, n)

    return msg_at_lvl_changed



  def refresh_autoclose_tstamp(self):
    """Recalculate the timestamp at which the window should be automatically
    closed
    """

    self.autoclose_tstamp = time() + auto_close_idle_window_timeout



  def unset_keep_above(self):
    """ If we requested that the window manager keep us above all other windows,
    release that request
    """

    if self.window_kept_above:
      self.set_keep_above(False)
      self.window_kept_above = False



  def on_clicked(self, w, e):
    """Called when clickable widgets get clicked on
    """

    self.unset_keep_above()
    self.refresh_autoclose_tstamp()



  def on_treeview_selection(self, selection):
    """Called when a treeview node is seleced
    """

    self.unset_keep_above()
    self.refresh_autoclose_tstamp()

    tree_model, i = selection.get_selected()

    # Do we have a selection?
    if i is not None:
      issuer, account, code = tree_model[i]

      # Copy the selected code both to the selection clipboard and the primary
      # clipboard
      self.selection_clipboard.set_text(code, -1)
      self.selprimary_clipboard.set_text(code, -1)

      self.set_statusbar(0, "Copied code {} ({}{}) into the clipboard".
				format(code, issuer + ":" if issuer else "",
					account))



  def on_cfg_entry_update(self, entry):
    """Called when any of the configuration entries are changed or activated
    """

    self.unset_keep_above()
    self.refresh_autoclose_tstamp()

    self.reader = self.reader_entry.get_text()
    self.oath_pwd = self.oath_pwd_entry.get_text()
    self.oath_pwd_remember = self.oath_pwd_entry_checkbtn.get_active()

    # Save the configuration file and set it read/writeable by the the user only
    try:
      with open(self.cfgfile, "w") as f:

        print(self.reader, file = f)
        print(self.oath_pwd if self.oath_pwd_remember else "", file = f)
        print("Remember" if self.oath_pwd_remember else "Forget", file = f)

    except Exception as e:
      self.set_statusbar(1, "Error saving configuration: {}".format(e))
      return

    try:
      os.chmod(self.cfgfile, 0o600)

    except Exception as e:
      self.set_statusbar(1, "Error setting config file perms: {}".format(e))
      return

    self.set_statusbar(1, None)



  def on_filter_entry_update(self, entry):
    """Called when the filter entry is changed or activated
    """

    self.unset_keep_above()
    self.refresh_autoclose_tstamp()

    # Get the filter text and refilter if needed
    s = self.filter_entry.get_text()
    if s != self.current_filter:
      self.current_filter = s
      self.filter.refilter()



  def deactivate(self, w = None, e = None):
    """Ask the timeout function to stop whenever possible, then hide the window
    """

    # Ask the timeout function to stop
    self.stop_timeout_func = True

    # Hide the window
    self.hide()

    # Stop the spinner
    self.spinner.start()

    # Prevent the delete event from propagating
    return True



  def timeout_func(self):
    """Timeout function that gets called periodically, handles running the
    vkman utility and processing what it returns
    """

    # Has the authenticator been idle for too long?
    secs_to_autoclose = int(self.autoclose_tstamp - time())
    if secs_to_autoclose <= 0:
      self.deactivate()

    # Are we about to auto-close the window?
    elif secs_to_autoclose <= auto_close_idle_window_countdown:
      self.set_statusbar(2, "Idle - closing in {} seconds...".
				format(secs_to_autoclose))

    else:
      self.set_statusbar(2, None)

    # Is vkman not running?
    if self.vkman_proc is None:

      # If we've been asked to stop, do so
      if self.stop_timeout_func:
        self.activated = False
        return False

      # Start vkman
      cmd = [self.vkman, "-r", self.reader if self.reader else default_reader,
		"oath", "accounts", "code"]
      cmd += ["-p", self.oath_pwd] if self.oath_pwd else []

      try:
        self.vkman_proc = Popen(cmd, stdout = PIPE, stderr = PIPE)

      except Exception as e:
        if self.set_statusbar(0, "Error running {}: {}".format(self.vkman, e)):
          self.refresh_autoclose_tstamp()

    # vkman is running:
    else:

      # See if it has sent a return code yet
      errcode = self.vkman_proc.poll()

      # If it hasn't stopped yet, keep going
      if errcode is None:
        return True

      # It has stopped: recover its stdout and stderr
      stdout_lines = self.vkman_proc.communicate()[0].\
			decode("utf-8").splitlines()
      stderr_lines = self.vkman_proc.communicate()[1].\
			decode("utf-8").splitlines()

      self.vkman_proc = None

      # Did the command return an error code?
      if errcode:

        # If we got a connection-related error, either there's no tag in the
        # field or it doesn't couple well, so don't consider this an error.
        # Only report any other errors to the user
        if "Failed to connect" in stderr_lines[0] or \
		"CardConnectionException" in stderr_lines[-1]:
          if self.last_scan_was_error:
            self.set_statusbar(0, None)
          self.last_scan_was_error = False

        else:
          if self.set_statusbar(0, "Error running {}{}".format(self.vkman,
						"" if not stderr_lines else \
						": " + stderr_lines[0])):
            self.refresh_autoclose_tstamp()
          self.last_scan_was_error = True

        return True

      # Did the command fail to return anything on stdout?
      if not stdout_lines:

        if self.set_statusbar(0, "Error: {} returned nothing".
				format(self.vkman)):
          self.refresh_autoclose_tstamp()
          self.last_scan_was_error = True

        return True

      # Process the lines returned by vkman
      iacs = []
      for l in stdout_lines:

        # Did the command return a malformed line?
        m = re.findall("^((.*):)?([^:]*\S)\s+([0-9]{6,10})\s*$", l)
        if not m:

          if self.set_statusbar(0, "Error: {} returned a malformed line: {}".
					format(self.vkman, l)):
            self.refresh_autoclose_tstamp()
          self.last_scan_was_error = True

          return True

        iacs.append(m[0][1:])

      # Replace the data in the liststore with the new data returned by vkman
      self.liststore.clear()
      for iac in iacs:
        self.liststore.append(iac)

      if self.set_statusbar(0, "Successfully read {} codes".format(len(iacs))):
        self.refresh_autoclose_tstamp()

      self.last_scan_was_error = False

    return True



### Main routine
def main():

  # Parse the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-v", "--vkman",
	help = "Path to the vkman utility. Default: {}".
		format(default_vkman),
	type = str,
	default = default_vkman)

  args = argparser.parse_args()

  # Run the app indicator
  tray_item(args.vkman)



### Jump to the main routine
if __name__ == "__main__":
  exit(main())
