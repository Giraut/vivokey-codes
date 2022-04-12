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
returned are displayed in the list. If an account is a Steam account (i.e. the
issuer is "Steam"), the TOTP code will be a 5-letter Steam code.

Select one entry to copy the code into the clipboard. The code may be pasted
into any application with right-click-paste, Ctrl-V or with the middle-click.

If background reading is enabled, the authenticator's panel automatically
appears upon successfully reading new codes.

If close on select is enabled, the authenticator's panel automatically closes
when a code is selected.
"""

### Parameters
default_reader = "0"
config_file = "~/.vivokey_codes.cfg"

codes_deprecation_timeout = 30 #s
auto_close_idle_window_timeout = 120 #s
auto_close_idle_window_countdown = 30 #s
error_message_clear_timeout = 3 #s

title = "Vivokey Codes"
icon = "vivokey_codes"
min_visible_list_lines = 10

tray_item_id = "vivokey_codes"
proc_title = "vivokey_codes"

sample_issuer_string = "Acme, Inc. (International Foobar Division)"
sample_account_string = "oleg.mcnoleg@acme-incorporated-international.com"
sample_code_string = "8888888888"



### Modules
import re
import os
import sys
import hmac
import hashlib
from time import time
from struct import pack, unpack
from random import randint
import smartcard.scard as sc
from signal import signal, SIGCHLD
from setproctitle import setproctitle
from multiprocessing import Process, Queue, Pipe
from queue import Empty

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

gi.require_version("AppIndicator3", "0.1")
from gi.repository import AppIndicator3



### Globals
sigchld_watch_p_in = None



### Classes
class tray_item():
  """Authenticator tray item
  """

  def __init__(self, sigchld_watch_p, codes_q, cmd_q, codes_reader_proc):
    """__init__ method
    """

    setproctitle(proc_title)

    self.codes_q = codes_q
    self.cmd_q = cmd_q
    self.codes_reader_proc = codes_reader_proc

    self.cfgfile = os.path.expanduser(config_file)

    # Watch the SIGCHLD watch pipe to terminate when the codes reader
    # process dies
    GLib.io_add_watch(sigchld_watch_p, GLib.IO_IN, Gtk.main_quit)

    # Start the authenticator in deactivated mode
    self.auth = authenticator(self.cfgfile, self.codes_q, self.cmd_q,
				self.codes_reader_proc)

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

  def __init__(self, cfgfile, codes_q, cmd_q, codes_reader_proc):
    """__init__ method
    """

    super().__init__(title = title)

    # Start deactivated
    self.activated = False

    self.cfgfile = cfgfile

    self.codes_q = codes_q
    self.cmd_q = cmd_q
    self.codes_reader_proc = codes_reader_proc

    self.codes_msg_counter = 0

    # Get the clipboards: selection clipboard for regular copy/paste and primary
    # clipboard for GNOME-style middle-click paste
    self.selection_clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
    self.selprimary_clipboard = Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY)

    # Try to read the configuration file, fail silently
    self.reader = None
    self.bg_read_enabled = False
    self.close_on_select = False
    self.oath_pwd = None
    self.oath_pwd_remember = False

    try:
      with open(self.cfgfile, "r") as f:

        params = f.read().splitlines()

    except Exception as e:
      params = []

    if len(params) == 5 and params[1] in ("Enabled", "Disabled") and \
				params[2] in ("Close", "Keep") and \
				params[4] in ("Remember", "Forget"):
      self.reader, self.bg_read_enabled, self.close_on_select, \
				self.oath_pwd, self.oath_pwd_remember = params
      self.bg_read_enabled = self.bg_read_enabled == "Enabled"
      self.close_on_select = self.close_on_select == "Close"
      self.oath_pwd_remember = self.oath_pwd_remember == "Remember"

    # Set the readers regex and OATH password for the first time
    self.cmd_q.put(("SETRDR", self.reader))
    self.cmd_q.put(("SETPWD", self.oath_pwd))

    self.stop_timeout_func = False

    self.current_list_data = []
    self.codes_deprecation_tstamp = None

    self.current_filter = ""
    self.statusbar_messages = [None] * 3

    self.last_errmsg_clear_tstamp = None

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
    self.treeview.connect("button_press_event", self.on_clicked)
    self.treeview_changed_handler_id = None

    # Get and set the text renderer
    self.renderer = Gtk.CellRendererText()
    self.renderer.set_fixed_height_from_font(1)

    # Calculate the size in pixels of a typical issuer, account and code
    text_widths = [0, 0, 0]
    for i, s in enumerate([sample_issuer_string,
				sample_account_string,
				sample_code_string]):
      pango = self.treeview.create_pango_layout(s)
      text_widths[i], text_height = pango.get_pixel_size()

    for i, column_title in enumerate(["Issuer", "Account", "Code"]):
      if i < 2:
        column = Gtk.TreeViewColumn(column_title, self.renderer, text = i)
      else:
        column = Gtk.TreeViewColumn(column_title, self.renderer, markup = i)

      column.set_min_width(text_widths[i])
      column.set_expand(True)
      self.treeview.append_column(column)

    # Create the text entry for the reader, with a label, a "enable
    # background reading" check button and a "close on select" check button
    self.reader_entry_label = Gtk.Label(label = "PC/SC Reader:")

    self.reader_entry = Gtk.Entry()
    self.reader_entry.set_placeholder_text(default_reader)
    if self.reader:
      self.reader_entry.set_text(self.reader)
    self.reader_entry.connect("activate", self.on_cfg_entry_update)
    self.reader_entry.connect("changed", self.on_cfg_entry_update)
    self.reader_entry.connect("button_press_event", self.on_clicked)

    self.enable_bg_read_checkbtn = Gtk.CheckButton(label = "enable background "
								"reading")
    self.enable_bg_read_checkbtn.set_active(self.bg_read_enabled)
    self.enable_bg_read_checkbtn.connect("toggled", self.on_cfg_entry_update)

    self.close_on_select_checkbtn = Gtk.CheckButton(label = "close on select")
    self.close_on_select_checkbtn.set_active(self.close_on_select)
    self.close_on_select_checkbtn.connect("toggled", self.on_cfg_entry_update)

    self.reader_entry_row = Gtk.HBox()

    self.reader_entry_row.pack_start(self.reader_entry_label,
						expand = False, fill = False,
						padding = 1)

    self.reader_entry_row.pack_start(self.reader_entry,
						expand = True, fill = True,
						padding = 1)

    self.reader_entry_row.pack_start(self.enable_bg_read_checkbtn,
						expand = False, fill = False,
						padding = 1)

    self.reader_entry_row.pack_end(self.close_on_select_checkbtn,
						expand = False, fill = False,
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

    # Create the status bar
    self.statusbar = Gtk.Statusbar()

    self.statusbar_row = Gtk.HBox()

    self.statusbar_row.pack_start(self.statusbar,
					expand = True, fill = True,
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

    # If background reading is enabled, start the periodic timeout function and
    # make it run every .2 seconds before activating the authenticator
    if self.bg_read_enabled:

      self.stop_timeout_func = False
      GLib.timeout_add(200, self.timeout_func)

      # Trigger the first codes read
      self.codes_msg_counter += 1
      self.cmd_q.put(("GET", self.codes_msg_counter))



  def activate(self, _ = None):
    """Activate the authenticator - i.e. unhide the window and start the
    periodic timeout function that triggers reads if background reading is
    disabled
    """

    # If we're already activated, we have nothing to do
    if self.activated:
      return

    self.activated = True

    self.refresh_autoclose_tstamp()

    # Clear the liststore and the status bar, so the user is presented with a
    # fresh screen
    self.current_list_data = []
    self.codes_deprecation_tstamp = None

    self.liststore.clear()
    for i in range(len(self.statusbar_messages)):
      self.set_statusbar(i, None)

    # Start the periodic timeout function and make it run every .2 seconds
    # if it isn't already running
    if not self.bg_read_enabled:

      self.stop_timeout_func = False
      GLib.timeout_add(200, self.timeout_func)

      # Trigger the first codes read
      self.codes_msg_counter += 1
      self.cmd_q.put(("GET", self.codes_msg_counter))

    # Ask the window manager to keep it above all the other windows until we
    # regain focus
    self.set_keep_above(True)
    self.window_kept_above = True

    # Show the window
    self.show_all()



  def deactivate(self, w = None, e = None):
    """Ask the timeout function to stop whenever possible, then hide the window
    """

    # Ask the timeout function to stop if background reading is disabled
    if not self.bg_read_enabled:
      self.stop_timeout_func = True

    # Hide the window
    self.hide()

    self.activated = False

    # Prevent the delete event from propagating
    return True



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



  def set_list(self, list_data, codes_deprecated = False):
    """Set the data in the liststore. If codes_deprecated if asserted, the
    codes are shown in light, bold otherwise.
    """

    # Disconnect the treeview from the "changed" signal while we change the list
    if self.treeview_changed_handler_id is not None:
      self.treeview_select.disconnect(self.treeview_changed_handler_id)

    # Clear the list
    self.liststore.clear()

    # Fill the list with the new data
    for i, a, c in list_data:
      self.liststore.append([i, a, '<span weight="{}">{}</span>'.
				format("light" if codes_deprecated else "bold",
					c)])

    # Reconnect the treeview to the "changed" signal
    self.treeview_changed_handler_id = self.treeview_select.connect("changed",
						self.on_treeview_selection)



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

      # Strip the markup from the code
      code = re.sub("<.*?>", "", code)

      # Copy the selected code both to the selection clipboard and the primary
      # clipboard
      self.selection_clipboard.set_text(code, -1)
      self.selprimary_clipboard.set_text(code, -1)

      self.set_statusbar(0, "Copied code {} ({}{}) into the clipboard".
				format(code, issuer + ":" if issuer else "",
					account))

      # If close on select is enabled, deactivate the authenticator
      if self.close_on_select:
        self.deactivate()



  def on_cfg_entry_update(self, entry):
    """Called when any of the configuration entries are changed or activated
    """

    self.unset_keep_above()
    self.refresh_autoclose_tstamp()

    self.reader = self.reader_entry.get_text()
    self.bg_read_enabled = self.enable_bg_read_checkbtn.get_active()
    self.close_on_select = self.close_on_select_checkbtn.get_active()
    self.oath_pwd = self.oath_pwd_entry.get_text()
    self.oath_pwd_remember = self.oath_pwd_entry_checkbtn.get_active()

    # Tell the codes reader process the readers regex and OATH password
    # need changing
    self.cmd_q.put(("SETRDR", self.reader))
    self.cmd_q.put(("SETPWD", self.oath_pwd))

    # Save the configuration file and set it read/writeable by the the user only
    try:
      with open(self.cfgfile, "w") as f:

        print(self.reader, file = f)
        print("Enabled" if self.bg_read_enabled else "Disabled", file = f)
        print("Close" if self.close_on_select else "Keep", file = f)
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



  def timeout_func(self):
    """Timeout function that gets called periodically and tries to get codes
    from the smartcard
    """

    # If we're asked to stop, do so
    if self.stop_timeout_func:
      return False

    now = time()

    # Is the authenticator activated?
    if self.activated:

      # Has the authenticator been idle for too long?
      secs_to_autoclose = int(self.autoclose_tstamp - now)
      if secs_to_autoclose <= 0:
        self.deactivate()

      # Are we about to auto-close the window?
      elif secs_to_autoclose <= auto_close_idle_window_countdown:
        self.set_statusbar(2, "Idle - closing in {} seconds...".
				format(secs_to_autoclose))

      else:
        self.set_statusbar(2, None)

      # Are the codes currently displayed in the list deprecated?
      if self.codes_deprecation_tstamp is not None and \
		now >= self.codes_deprecation_tstamp:
        self.set_list(self.current_list_data, codes_deprecated = True)
        self.codes_deprecation_tstamp = None

    # Try to get read results from the codes pipe
    rctr = None
    while rctr != self.codes_msg_counter:
      try:
        rctr, errmsg, errcritical, iacs = self.codes_q.get(block = False)

      except Empty:
        return True

    # Trigger another codes read rightaway
    self.codes_msg_counter += 1
    self.cmd_q.put(("GET", self.codes_msg_counter))

    # Did we get an error mesage?
    if errmsg:

      # If we got a non-critical error - either there's no tag in the
      # field, it doesn't couple well or the transfer was cut short - don't
      # consider it an error. But do report other errors to the user
      if errcritical:
        if self.set_statusbar(0, "Error getting codes: {}".format(errmsg)):
          self.refresh_autoclose_tstamp()
        self.last_errmsg_clear_tstamp = time() + error_message_clear_timeout

      else:
        if self.last_errmsg_clear_tstamp is not None and \
		time() >= self.last_errmsg_clear_tstamp:
          self.set_statusbar(0, None)
          self.last_errmsg_clear_tstamp = None

      return True

    # If the authenticator is currently deactivated, activate it
    if not self.activated:
      self.activate()

    self.set_statusbar(0, "Successfully read {} codes".format(len(iacs)))
    self.last_errmsg_clear_tstamp = None

    # If the list hasn't changed, don't update the data in the liststore
    if len(iacs) == len(self.current_list_data) and all([e[0] == e[1] \
				for e in zip(iacs, self.current_list_data)]):
      return True

    # Update the code deprecation timeout
    self.codes_deprecation_tstamp = time() + codes_deprecation_timeout

    # Replace the data in the liststore with the new data
    self.current_list_data = iacs
    self.set_list(self.current_list_data, codes_deprecated = False)

    self.refresh_autoclose_tstamp()

    return True



class pcsc_oath():
  """Class to get the list of TOTP codes from an OATH applet running on an
  ISO14443-4 smartcard using PC/SC
  """

  # Defines
  DEFAULT_OATH_AID = "a0000007470061fc54d5"	# Vivokey OTP applet
  DEFAULT_PERIOD = 30 #s

  INS_SELECT = 0xa4
  P1_SELECT = 0x04
  P2_SELECT = 0x00

  INS_VALIDATE = 0xa3

  INS_CALCULATE = 0xa2
  INS_CALCULATE_ALL = 0xa4
  P2_CALCULATE_FULL = 0x00
  P2_CALCULATE_TRUNCATED = 0x01

  INS_SEND_REMAINING = 0xa5

  SW1_OK = 0x90
  SW2_OK = 0x00

  SW1_AUTH_ERROR = 0x69
  SW2_AUTH_REQUIRED = 0x82
  SW2_AUTH_FAILED = 0x84

  SW1_WRONG_SYNTAX = 0x6a
  SW2_WRONG_SYNTAX = 0x80

  SW1_MORE_DATA = 0x61

  NAME_TAG = 0x71
  CHALLENGE_TAG = 0x74
  RESPONSE_TAG = 0x75
  FULL_TAG = 0x75
  TRUNCATED_TAG = 0x76

  STEAM_CODE_CHARSET = "23456789BCDFGHJKMNPQRTVWXY"



  def __init__(self, oath_aid = DEFAULT_OATH_AID, period = DEFAULT_PERIOD):
    """__init__ method
    """

    self.steam_code_charset_len = len(self.STEAM_CODE_CHARSET)

    self.readers_regex = "^.*$"
    self.oath_aid = list(bytes.fromhex(oath_aid))
    self.period = period

    self.all_readers = []
    self.hcontext = None

    self.reader = None

    self.oath_pwd = None



  def set_readers_regex(self, reader):
    """Construct the readers regex from the string supplied by the user and
    force the reader to be updated
    """

    self.readers_regex = "^.*{}.*$".format(reader)
    self.all_readers = []



  def set_oath_pwd(self, oath_pwd):
    """Set the OATH password to use at the next get_code()
    """

    self.oath_pwd = oath_pwd



  def _send_apdu(self, hcard, dwActiveProtocol, apdu):
    """Send an APDU command, get and collate the response.
    Returns (None, None, r, response) if no error,
    (errmsg, err_critical_flag, None, None) otherwise.
    """

    try:
      r, response = sc.SCardTransmit(hcard, dwActiveProtocol, apdu)

    except Exception as e:
      return (repr(e), True, None, None)

    if len(response) < 2:
      return ("APDU response too short", False, None, None)

    while response[-2] == self.SW1_MORE_DATA:

      try:
        r, chunk = sc.SCardTransmit(hcard, dwActiveProtocol,
					[0, self.INS_SEND_REMAINING, 0, 0])

      except Exception as e:
        return (repr(e), True, None, None)

      if len(chunk) < 2:
        return ("APDU response too short", False, None, None)

      response = response[:-2] + chunk

    return (None, None, r, response)



  def _tlv(self, tag, data):
    """Encapsulate data in a TLV structure
    """

    l = len(data)

    return [tag] + ([l] if l < 0xff else [0xff, l >> 8, l & 0xff]) + list(data)



  def _untlv(self, data, do_dict = False):
    """Extract TLV values into a list of [tag, value], or a tag_keyed dictionary
    if do_dict is asserted.
    Returns (None, list or dict) if no error, (errmsg, None) otherwise.
    """

    ld = {} if do_dict else []
    errmsg = None

    while data and not errmsg:

      # Check the overall length of the TLV
      if len(data) < 2 or (data[1] == 0xff and len(data) < 4):
        errmsg = "TLV too short in APDU response"
        break

      # Get the tag
      t = data[0]

      # Get the length of the TLV and remove the tag and length from the data
      l = data[1]

      if l == 0xff:
        l = (data[2] << 8) | data[3]
        data = data[4:]

      else:
        data = data[2:]

      # Get the value and check that it has the advertised length
      v = bytes(data[:l])

      if len(v) < l:
        errmsg = "TLV value too short in APDU response"
        break

      # Remove the value from the data
      data = data[l:]

      # Add the tag and value to our list or dictionary
      if do_dict:
        ld[t] = v

      else:
        ld.append([t, v])

    return (errmsg, None) if errmsg else (None, ld)



  def get_codes(self):
    """Try to establish communication with the smartcard, select the OATH AID,
    validate the OATH password if needed, then get TOTP codes.
    Returns (None, None, ...) if no error, (errmsg, err_critical_flag, None)
    otherwise.
    """

    hcard = None

    errmsg = None
    errcritical = True
    oath_codes = []

    disconnect_card = False
    release_ctx = False

    while True:

      # If we arrive here needing to either disconnect the card or release the
      # PC/SC resource manager context, do so and break the loop
      if disconnect_card or release_ctx:

        if disconnect_card:
          try:
            sc.SCardDisconnect(hcard, sc.SCARD_UNPOWER_CARD)
          except:
            pass

        if release_ctx:
          try:
            sc.SCardReleaseContext(self.hcontext)
          except:
            pass
          del(self.hcontext)
          self.hcontext = None

        break

      # Get the PC/SC resource manager context
      if not self.hcontext:
        try:
          r, self.hcontext = sc.SCardEstablishContext(sc.SCARD_SCOPE_USER)

        except Exception as e:
          errmsg = "error getting PC/SC resource manager context: {}".format(e)
          break

        if r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "cannot establish PC/SC resource manager context"
          continue

      # Get the current list of readers
      try:
        _, all_readers_new = sc.SCardListReaders(self.hcontext, [])

      except Exception as e:
        release_ctx = True
        errmsg = "error getting the list of readers: {}".format(e)
        continue

      if not all_readers_new:
        self.all_readers = []
        errmsg = "no readers"
        break

      # Get the first reader that matches the regex
      if all_readers_new != self.all_readers:
        self.all_readers = all_readers_new

        for r in self.all_readers:
          if re.match(self.readers_regex, r, re.I):
            self.reader = r
            break

        else:
          self.reader = None

      # Do we have a reader to read from?
      if self.reader is None:
        errmsg = "no matching readers"
        break

      # Whatever happens next, release the context so other application may
      # access the card if we can't
      release_ctx = True

      # Connect to the smartcard
      try:
        r, hcard, dwActiveProtocol = sc.SCardConnect(self.hcontext,
						self.reader,
						sc.SCARD_SHARE_SHARED,
						sc.SCARD_PROTOCOL_T0 | \
						sc.SCARD_PROTOCOL_T1)

      except Exception as e:
        errmsg = "error connecting to the smartcard: {}".format(e)
        continue

      if r != sc.SCARD_S_SUCCESS:
        errmsg = "error connecting to the smartcard"
        errcritical = False
        break

      # Whatever happens next, try to disconnect the card before returning
      disconnect_card = True

      # Select the OATH AID
      errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_SELECT, self.P1_SELECT,
					self.P2_SELECT,
					len(self.oath_aid)] + self.oath_aid)

      if errmsg or r != sc.SCARD_S_SUCCESS:
        release_ctx = True
        errmsg = "error transmitting OATH AID selection command{}".format(
			": {}".format(errmsg) if errmsg else "")
        errcritical = ec
        continue

      # Did we get a response error?
      if response[-2:] != [self.SW1_OK, self.SW2_OK]:
        errmsg = "error {:02X}{:02X} from OATH AID selection command".format(
			response[-2], response[-1])
        errcritical = False
        continue

      errmsg, tlvs = self._untlv(response[:-2], do_dict = True)
      if errmsg:
        continue

      # Did we get a name tag?
      if self.NAME_TAG not in tlvs:
        errmsg = "Malformed APDU response: missing name tag in " \
			"AID selection command response"
        continue

      salt = tlvs[self.NAME_TAG]
      challenge = tlvs.get(self.CHALLENGE_TAG, None)

      # Do we have a password to validate?
      if self.oath_pwd:

        # If the token doesn't have a key, throw an error
        if challenge is None:
          errmsg = "password set but no password required"
          continue

        # Calculate our response to the token's challenge
        key = hashlib.pbkdf2_hmac("sha1", self.oath_pwd.encode("ascii"),
					salt, 1000, 16)
        response = hmac.new(key, challenge, "sha1").digest()
        data_tlv = self._tlv(self.RESPONSE_TAG, response)

        # Calculate our own challenge to the token
        challenge = [randint(0, 255) for _ in range(8)]
        data_tlv += self._tlv(self.CHALLENGE_TAG, challenge)

        # Validate the password
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_VALIDATE, 0, 0,
					len(data_tlv)] + data_tlv)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting VALIDATE command{}".format(
			": {}".format(errmsg) if errmsg else "")
          errcritical = ec
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:

          # Did the authentication fail?
          if response[-2:] == [self.SW1_AUTH_ERROR, self.SW2_AUTH_FAILED] or \
		response[-2:] == [self.SW1_WRONG_SYNTAX, self.SW2_WRONG_SYNTAX]:
            errmsg = "authentication failed"

          else:
            errmsg = "error {:02X}{:02X} from VALIDATE selection command".\
			format(response[-2], response[-1])
          continue

        errmsg, tlvs = self._untlv(response[:-2], do_dict = True)
        if errmsg:
          continue

        response = tlvs.get(self.RESPONSE_TAG, None)

        # Did the token send a response to our challenge?
        if response is None:
          errmsg = "Malformed APDU response: missing response from "\
			"VALIDATE command response"
          continue

        # Verify the response
        verification = hmac.new(key, bytes(challenge), "sha1").digest()
        if not hmac.compare_digest(response, verification):
          errmsg = "response from VALIDATE command does not match verification"
          continue

      else:

        # If the token has a key, throw an error
        if challenge is not None:
          errmsg = "password required"
          continue

      # Request the list of codes
      challenge = pack(">q", int(time() // self.period))
      challenge_tlv = self._tlv(self.CHALLENGE_TAG, challenge)
      errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_CALCULATE_ALL, 0,
					self.P2_CALCULATE_TRUNCATED,
					len(challenge_tlv)] + challenge_tlv)

      if errmsg or r != sc.SCARD_S_SUCCESS:
        release_ctx = True
        errmsg = "error transmitting CALCULATE_ALL command{}".format(
			": {}".format(errmsg) if errmsg else "")
        errcritical = ec
        continue

      # Did we get a response error?
      if response[-2:] != [self.SW1_OK, self.SW2_OK]:

        # Is authentication required?
        if response[-2:] == [self.SW1_AUTH_ERROR, self.SW2_AUTH_REQUIRED]:
          errmsg = "authentication required"

        else:
          errmsg = "error {:02X}{:02X} from CALCULATE_ALL command".format(
			response[-2], response[-1])
          errcritical = False

        continue

      # Decode the response, which should be a sequence of name and truncated
      # response TLV pairs
      errmsg, tlvs = self._untlv(response[:-2], do_dict = False)
      if errmsg:
        continue

      # Make sure we have only received pairs of NAME + TRUNCATED tags and
      # decode them
      i = -1
      for i, tlv in enumerate(tlvs):

        t, v = tlv

        # Check that we have the tag we should have at this position
        if t != (self.NAME_TAG, self.TRUNCATED_TAG)[i % 2]:
          errmsg = "Malformed APDU response: unexpected tag"
          break

        # Decode the name
        if t == self.NAME_TAG:

          # Check thet the value is a string
          try:
            v = v.decode("ascii")

          except:
            errmsg = "invalid name record {} in APDU".format(v)
            break

          # Check that the name is properly formatted as "issuer:account",
          # or "account" without issuer
          m = re.findall("^((.*):)?([^:]*\S)\s*$", v)
          if m:
            name = m[0][1:]

          else:
            errmsg = "malformed name record {} in APDU".format(v)
            break

        # Decode the truncated value
        elif t == self.TRUNCATED_TAG:

          # Check that the code record isn't empty
          if not v:
            errmsg = "empty code record in APDU".format(v)
            break

          # Check that the code has a valid number of digits
          if 6 <= v[0] <= 10:
            v = str((int.from_bytes(v[1:], "big") & 0x7fffffff) % 10 \
				** v[0]).rjust(v[0], "0")

          else:
            errmsg = "malformed code record {} in APDU".format(v)
            break

          # Add this issuer + account + code to our list
          oath_codes.append([name[0], name[1], v])

      if errmsg:
        continue

      if not (i % 2):
        errmsg = "Malformed APDU response: odd number of TLVs"
        continue

      # For all Steam accounts, request a new code calculation with full
      # response, calculate the Steam code then replace the truncated code
      # obtained earlier with the Steam code
      for i, name in enumerate([e[1] for e in tlvs if e[0] == self.NAME_TAG]):

        # Is this a Steam account?
        issuer = oath_codes[i][0]
        if issuer != "Steam":
          continue

        # Request a new calculation for this account
        name_tlv = self._tlv(self.NAME_TAG, name)
        errmsg, ec, r, response = self._send_apdu(hcard, dwActiveProtocol,
					[0, self.INS_CALCULATE, 0,
					self.P2_CALCULATE_FULL,
					len(name_tlv) + len(challenge_tlv)] + \
					name_tlv + challenge_tlv)

        if errmsg or r != sc.SCARD_S_SUCCESS:
          release_ctx = True
          errmsg = "error transmitting CALCULATE command{}".format(
			": {}".format(errmsg) if errmsg else "")
          errcritical = ec
          continue

        # Did we get a response error?
        if response[-2:] != [self.SW1_OK, self.SW2_OK]:
          errmsg = "error {:02X}{:02X} from CALCULATE command".format(
			response[-2], response[-1])
          errcritical = False
          continue

        # Decode the response, which should be a full code response TLV
        errmsg, tlvs_st = self._untlv(response[:-2], do_dict = False)
        if errmsg:
          continue

        if len(tlvs_st) != 1:
          errmsg = "Malformed APDU response: expected 1 TLV, got {}".\
			format(len(tlvs_st))
          break

        if tlvs_st[0][0] != self.FULL_TAG:
          errmsg = "Malformed APDU response: unexpected tag"
          break

        # Calculate the Steam code
        offset = tlvs_st[0][1][-1] & 0x0f
        n = unpack(">I", tlvs_st[0][1][offset + 1 : offset + 5])[0] & 0x7fffffff
        steam_code = ""
        for _ in range(5):
          steam_code += self.STEAM_CODE_CHARSET[n % self.steam_code_charset_len]
          n //= self.steam_code_charset_len

        # Replace the truncated code with the Steam code
        oath_codes[i][2] = steam_code

      if errmsg:
        continue

      # Sort the list of OATH codes by issuer + account
      oath_codes = sorted(oath_codes, key = lambda e: (e[0] + e[1]).upper())

      # All done
      break

    return (errmsg, errcritical, oath_codes)



### Routines
def pcsc_codes_reader(codes_q, cmd_q, ppid):
  """Function spawned as a separate process to get codes from the reader
  """

  setproctitle(proc_title + "_pcsc")

  # Create a PC/SC oath code reader instance
  po = pcsc_oath()

  while True:

    # Get a command and argument from the command queue
    try:
      cmd, arg = cmd_q.get(block = True, timeout = 1)

    except Empty:	# Timeout
      # Terminate if the PPID has changed (indicating that our parent process
      # has died)
      if os.getppid() != ppid:
        break

      continue

    # Terminate
    if cmd == "STOP":
      break

    # Set the PC/SC readers regex
    elif cmd == "SETRDR":
      po.set_readers_regex(arg if arg else default_reader)

    # Set the OATH password
    elif cmd == "SETPWD":
      po.set_oath_pwd(arg)

    # Read codes and return them through the codes pipe
    elif cmd == "GET":
      codes_q.put((arg,) + po.get_codes())



# SIGCHLD handler
def sigchld_handler(sig, fname):
  """SIGCHLD handler: send something down the SIGCHLD watch pipe to signal the
  death of the codes reader process to the Gtk program
  """

  global sigchld_watch_p_in

  sigchld_watch_p_in.send("\n")



### Mxin routine
def main():

  global sigchld_watch_p_in

  # Create a pipe to signal the death of the codes reader process to the Gtk
  # program and install the SIGCHLD handler
  sigchld_watch_p_in, sigchld_watch_p_out = Pipe()
  signal(SIGCHLD, sigchld_handler)

  # Create queues to receive codes from the codes reader process and to send
  # it commands
  codes_q = Queue()
  cmd_q = Queue()

  # Start the codes reader process
  codes_reader_proc = Process(target = pcsc_codes_reader,
				args = (codes_q, cmd_q, os.getpid()))
  codes_reader_proc.start()

  # Start the tray item
  tray_item(sigchld_watch_p_out, codes_q, cmd_q, codes_reader_proc)

  # Ask the codes reading process to stop nicely first, then send it SIGTERM,
  # then SIGKILL
  cmd_q.put(("STOP", None))
  codes_reader_proc.join(1)

  codes_reader_proc.terminate()
  codes_reader_proc.join(1)

  codes_reader_proc.kill()



### Jump to the main routine
if __name__ == "__main__":
  main()
