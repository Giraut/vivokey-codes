#!/usr/bin/python3
"""
GTK Authenticator to read TOTP codes from a Vivokey OTP applet, display them
and copy them into the clipboard.

This program starts minimized in the system tray. Click on the icon then select
"Get codes" to start the authenticator's panel.

As soon as the panel comes up, it starts polling the PC/SC reader whose name is
specified in the Reader field for a Vivokey token to read. When the panel is
closed, it stops polling the reader.

Present your Vivokey token to the reader. If the token is passworded, you can
set the password in the panel.

If a token is read successfully, the accounts and associated TOTP codes it
returned are displayed in the list. Select one entry to copy the code into the
clipboard.

This program uses the Vivokey Manager utility. See:

https://github.com/Giraut/vivokey-manager
"""

### Parameters
default_vkman = "/usr/bin/vkman"
default_reader = "0"
config_file = "~/.vivokey_codes.cfg"

title = "Vivokey Codes"
tray_item_id = "vivokey_codes"
tray_item_icon = "vivokey_codes"
min_visible_list_lines = 10

sample_issuer_string = "Acme, Inc. (International Foobar Division)"
sample_account_string = "oleg.mcnoleg@acme-incorporated-international.com"
sample_code_string = "0123456789"



### Modules
import re
import os
import gi
import argparse
from subprocess import Popen, PIPE

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

gi.require_version("AppIndicator3", "0.1")
from gi.repository import AppIndicator3



### Globals
vkman = default_vkman
authenticator_running = False
stop_timeout_func = False



### Classes
class authenticator(Gtk.Window):
  """Authenticator application proper
  """

  def __init__(self, cfgfile, reader, oath_pwd, oath_pwd_remember):
    """__init__ method
    """

    super().__init__(title = title)

    self.cfgfile = cfgfile

    self.reader = reader
    self.oath_pwd = oath_pwd
    self.oath_pwd_remember = oath_pwd_remember

    self.current_filter = ""

    self.vkman_proc = None

    self.set_border_width(10)

    # Get the clipboard
    self.clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)

    # Set up the grid in which the panel's elements are to be positioned
    self.grid = Gtk.Grid()
    self.add(self.grid)

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
    self.reader_entry.connect("activate", self.on_entry_update)
    self.reader_entry.connect("changed", self.on_entry_update)

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
    self.oath_pwd_entry.connect("activate", self.on_entry_update)
    self.oath_pwd_entry.connect("changed", self.on_entry_update)

    self.oath_pwd_entry_checkbtn = Gtk.CheckButton(label = "remember")
    self.oath_pwd_entry_checkbtn.set_active(self.oath_pwd_remember)
    self.oath_pwd_entry_checkbtn.connect("toggled", self.on_entry_update)

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

    # Create the text entry for the filter string, with a label
    self.filter_entry = Gtk.Entry()
    self.filter_entry.set_placeholder_text("None")
    self.filter_entry.connect("activate", self.on_entry_update)
    self.filter_entry.connect("changed", self.on_entry_update)

    self.filter_entry_label = Gtk.Label(label = "Filter:")

    self.filter_entry_row = Gtk.HBox()
    self.filter_entry_row.pack_start(self.filter_entry_label,
						expand = False, fill = True,
						padding = 1)
    self.filter_entry_row.pack_end(self.filter_entry,
						expand = True, fill = True,
						padding = 1)

    # Create the status bar
    self.statusbar = Gtk.Statusbar()

    self.statusbar_with_labeled_frame = Gtk.Frame(label = "Status")
    self.statusbar_with_labeled_frame.add(self.statusbar)

    # Put everything together: put the treeview in a scrollwindow and the text
    # entry rows above and below
    self.grid.attach(self.reader_entry_row, 0, 0, 1, 10)

    self.grid.attach_next_to(self.oath_pwd_entry_row,
				self.reader_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.scrollable_treelist = Gtk.ScrolledWindow()
    self.scrollable_treelist.set_hexpand(True)
    self.scrollable_treelist.set_vexpand(True)
    self.scrollable_treelist.set_min_content_width(sum(text_widths))
    self.scrollable_treelist.set_min_content_height(1.5 * text_height * \
							min_visible_list_lines)

    self.grid.attach_next_to(self.scrollable_treelist,
				self.oath_pwd_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.grid.attach_next_to(self.filter_entry_row,
				self.scrollable_treelist,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.grid.attach_next_to(self.statusbar_with_labeled_frame,
				self.filter_entry_row,
				Gtk.PositionType.BOTTOM, 1, 1)

    self.scrollable_treelist.add(self.treeview)

    # Focus on the filter entry by default
    self.filter_entry.grab_focus()

    # Start the periodic timeout function and make it run every .1 second
    GLib.timeout_add(100, self.timeout_func)

    self.show_all()



  def filter_func(self, tree_model, i, data):
    """Tests if the issuer or the account in the row contain the filter text
    """

    return not self.current_filter or \
	re.search(self.current_filter, tree_model[i][0], re.I) is not None or \
	re.search(self.current_filter, tree_model[i][1], re.I) is not None



  def on_treeview_selection(self, selection):
    """Called when a treeview node is seleced
    """

    tree_model, i = selection.get_selected()

    # Do we have a selection?
    if i is not None:
      issuer, account, code = tree_model[i]

      # Copy the selected code to the clipboard
      self.clipboard.set_text(code, -1)

      self.statusbar.pop(0)
      self.statusbar.push(0, "Copied code {} ({}{}) into the clipboard".
				format(code, issuer + ":" if issuer else "",
					account))



  def on_entry_update(self, entry):
    """Called when any of the text entry boxes is updated
    """

    save_cfgfile = False

    # Get the reader
    s = self.reader_entry.get_text()
    if s != self.reader:
      save_cfgfile = True
      self.reader = s

    # Get the OATH password
    s = self.oath_pwd_entry.get_text()
    if s != self.oath_pwd:
      save_cfgfile = True
      self.oath_pwd = s

    # Get the state of the "remember" check button
    s = self.oath_pwd_entry_checkbtn.get_active()
    if s != self.oath_pwd_remember:
      save_cfgfile = True
      self.oath_pwd_remember = s

    # Save the configuration file if needed and set it read/writeable by the
    # the user only
    error_saving = False
    self.statusbar.pop(0)

    if save_cfgfile:
      try:
        with open(self.cfgfile, "w") as f:

          print(self.reader, file = f)
          print(self.oath_pwd if self.oath_pwd_remember else "", file = f)
          print("Remember" if self.oath_pwd_remember else "Forget", file = f)

      except Exception as e:
        error_saving = True
        self.statusbar.push(0, "Error saving configuration: {}".format(e))

      if not error_saving:
        try:
          os.chmod(self.cfgfile, 0o600)

        except Exception as e:
          error_saving = True
          self.statusbar.push(0, "Error setting config file perms: {}".
				format(e))

    # Get the filter text and refilter if needed
    s = self.filter_entry.get_text()
    if s != self.current_filter:
      self.current_filter = s
      self.filter.refilter()



  def timeout_func(self):
    """Timeout function that gets called periodically, handles running the
    vkman utility and processing what it returns
    """

    global vkman
    global stop_timeout_func

    # Is vkman not running?
    if self.vkman_proc is None:

      # If we've been asked to stop, do so
      if stop_timeout_func:
        stop_timeout_func = False
        return False

      # Start vkman
      cmd = [vkman, "-r", self.reader if self.reader else default_reader,
		"oath", "accounts", "code"]
      cmd += ["-p", self.oath_pwd] if self.oath_pwd else []

      try:
        self.vkman_proc = Popen(cmd, stdout = PIPE, stderr = PIPE)

      except Exception as e:
        self.statusbar.pop(0)
        self.statusbar.push(0, "Error running {}: {}".format(vkman, e))

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

        # If we got a connection-related error, something went wrong trying to
        # read the token, but it's nothing to write into the status bar about
        if not ("Failed to connect" in stderr_lines[0] or \
		"CardConnectionException" in stderr_lines[-1]):
          self.statusbar.pop(0)
          self.statusbar.push(0, "Error running {}{}".format(vkman,
						"" if not stderr_lines else \
						": " + stderr_lines[0]))
        return True

      # Did the command fail to return anything on stdout?
      if not stdout_lines:
        self.statusbar.pop(0)
        self.statusbar.push(0, "Error: {} returned nothing".format(vkman))
        return True

      # Process the lines returned by vkman
      iacs = []
      for l in stdout_lines:

        # Did the command return a malformed line?
        m = re.findall("^((.*):)?([^:]*\S)\s+([0-9]{6,10})\s*$", l)
        if not m:
          self.statusbar.pop(0)
          self.statusbar.push(0, "Error: {} returned a malformed line: {}".
					format(vkman, l))
          return True

        iacs.append(m[0][1:])

      # Replace the data in the liststore with the new data returned by vkman
      self.liststore.clear()
      for iac in iacs:
        self.liststore.append(iac)

      self.statusbar.pop(0)
      self.statusbar.push(0, "Successfully read {} codes!".format(len(iacs)))

    return True



### App indicator callbacks
def menu():
  """Create and populate the app indicator's menu
  """

  menu = Gtk.Menu()

  cmd_getcodes = Gtk.MenuItem(label = 'Get codes')
  cmd_getcodes.connect('activate', getcodes)
  menu.append(cmd_getcodes)

  exit = Gtk.MenuItem(label = 'Exit')
  exit.connect('activate', quit)
  menu.append(exit)

  menu.show_all()

  return menu



def getcodes(_):
  """Open the authenticator window
  """

  global authenticator_running
  global stop_timeout_func

  if authenticator_running:
    return

  authenticator_running = True

  # Try to read the configuration file, fail silently
  reader = None
  oath_pwd = None
  oath_pwd_remember = False

  cfgfile = os.path.expanduser(config_file)
  try:
    with open(cfgfile, "r") as f:

      params = f.read().splitlines()

      if len(params) == 3 and params[2] in ("Remember", "Forget"):
        reader, oath_pwd, oath_pwd_remember = params
        oath_pwd_remember = oath_pwd_remember == "Remember"

  except:
    pass

  # Start the authenticator
  win = authenticator(cfgfile, reader, oath_pwd, oath_pwd_remember)
  win.connect("destroy", Gtk.main_quit)
  win.show_all()
  Gtk.main()

  # Ask the periodic timeout function to stop whenever possible
  stop_timeout_func = True

  authenticator_running = False



def quit(_):
  """Quit the app indicator
  """

  Gtk.main_quit()



### Main routine
def main():

  global vkman

  # Parse the command line arguments
  argparser = argparse.ArgumentParser()

  argparser.add_argument(
	"-v", "--vkman",
	help = "Path to the vkman utility. Default: <user>@{}".
		format(default_vkman),
	type = str,
	default = default_vkman)

  args = argparser.parse_args()

  vkman = args.vkman

  # Create the app indicator
  indicator = AppIndicator3.Indicator.new(tray_item_id, tray_item_icon,
						AppIndicator3.IndicatorCategory.
						APPLICATION_STATUS)
  indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
  indicator.set_title(title)
  indicator.set_menu(menu())

  # Run the app indicator
  Gtk.main()



### Jump to the main routine
if __name__ == "__main__":
  exit(main())
