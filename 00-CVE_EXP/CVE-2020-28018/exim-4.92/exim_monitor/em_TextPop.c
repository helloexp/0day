/***********************************************************
Copyright 1989 by the Massachusetts Institute of Technology,
Cambridge, Massachusetts.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Digital or MIT not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

DIGITAL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
DIGITAL BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/


/****************************************************************************
* Modified by Philip Hazel for use with Exim. The "replace" and "insert     *
* file" features of the search facility have been removed.  Also took out   *
* the declaration of sys_errlist, as it isn't used and causes trouble on    *
* some systems that declare it differently. September 1996.                 *
* Added the arguments into the static functions declared at the head, to    *
* stop some compiler warnings. August 1999.                                 *
* Took out the separate declarations of errno and sys_nerr at the start,    *
* because they too aren't actually used, and the declaration causes trouble *
* on some systems. December 2002.                                           *
****************************************************************************/


/************************************************************
 *
 * This file is broken up into three sections one dealing with
 * each of the three popups created here:
 *
 * FileInsert, Search, and Replace.
 *
 * There is also a section at the end for utility functions
 * used by all more than one of these dialogs.
 *
 * The following functions are the only non-static ones defined
 * in this module.  They are located at the beginning of the
 * section that contains this dialog box that uses them.
 *
 * void _XawTextInsertFileAction(w, event, params, num_params);
 * void _XawTextDoSearchAction(w, event, params, num_params);
 * void _XawTextDoReplaceAction(w, event, params, num_params);
 * void _XawTextInsertFile(w, event, params, num_params);
 *
 *************************************************************/

#include <X11/IntrinsicP.h>
#include <X11/StringDefs.h>
#include <X11/Shell.h>

#include <X11/Xaw/TextP.h>
#include <X11/Xaw/AsciiText.h>
#include <X11/Xaw/Cardinals.h>
#include <X11/Xaw/Command.h>
#include <X11/Xaw/Form.h>
#include <X11/Xaw/Toggle.h>
#include <X11/Xmu/CharSet.h>
#include <stdio.h>
#include <X11/Xos.h>		/* for O_RDONLY */
#include <errno.h>

/* extern int errno, sys_nerr; */
/* extern char* sys_errlist[]; */

#define DISMISS_NAME  ("cancel")
#define DISMISS_NAME_LEN 6
#define FORM_NAME     ("form")
#define LABEL_NAME    ("label")
#define TEXT_NAME     ("text")

#define R_OFFSET      1

/* Argument types added by PH August 1999 */

static void CenterWidgetOnPoint(Widget, XEvent *);
static void PopdownSearch(Widget, XtPointer, XtPointer);
static void InitializeSearchWidget(struct SearchAndReplace *,
  XawTextScanDirection, Boolean);
static void  SetResource(Widget, char *, XtArgVal);
static void  SetSearchLabels(struct SearchAndReplace *, String, String,
  Boolean);
static Widget CreateDialog(Widget, String, String,
  void (*)(Widget, char *, Widget));
static Widget  GetShell(Widget);
static void SetWMProtocolTranslations(Widget w);
static Boolean DoSearch(struct SearchAndReplace *);
static String GetString(Widget);

static void AddSearchChildren(Widget, char *, Widget);

static char radio_trans_string[] =
    "<Btn1Down>,<Btn1Up>:   set() notify()";

static char search_text_trans[] =
  "~Shift<Key>Return:      DoSearchAction(Popdown) \n\
   Ctrl<Key>c:             PopdownSearchAction() \n\
   ";



/************************************************************
 *
 * This section of the file contains all the functions that
 * the search dialog box uses.
 *
 ************************************************************/

/*	Function Name: _XawTextDoSearchAction
 *	Description: Action routine that can be bound to dialog box's
 *                   Text Widget that will search for a string in the main
 *                   Text Widget.
 *	Arguments:   (Standard Action Routine args)
 *	Returns:     none.
 *
 * Note:
 *
 * If the search was successful and the argument popdown is passed to
 * this action routine then the widget will automatically popdown the
 * search widget.
 */

/* ARGSUSED */
void
_XawTextDoSearchAction(w, event, params, num_params)
Widget w;
XEvent *event;
String * params;
Cardinal * num_params;
{
  TextWidget tw = (TextWidget) XtParent(XtParent(XtParent(w)));
  Boolean popdown = FALSE;

  if ( (*num_params == 1) &&
       ((params[0][0] == 'p') || (params[0][0] == 'P')) )
      popdown = TRUE;

  if (DoSearch(tw->text.search) && popdown)
    PopdownSearch(w, (XtPointer) tw->text.search, NULL);
}

/*	Function Name: _XawTextPopdownSearchAction
 *	Description: Action routine that can be bound to dialog box's
 *                   Text Widget that will popdown the search widget.
 *	Arguments:   (Standard Action Routine args)
 *	Returns:     none.
 */

/* ARGSUSED */
void
_XawTextPopdownSearchAction(w, event, params, num_params)
Widget w;
XEvent *event;
String * params;
Cardinal * num_params;
{
  TextWidget tw = (TextWidget) XtParent(XtParent(XtParent(w)));

  PopdownSearch(w, (XtPointer) tw->text.search, NULL);
}

/*	Function Name: PopdownSearch
 *	Description: Pops down the search widget and resets it.
 *	Arguments: w - *** NOT USED ***.
 *                 closure - a pointer to the search structure.
 *                 call_data - *** NOT USED ***.
 *	Returns: none
 */

/* ARGSUSED */
static void
PopdownSearch(w, closure, call_data)
Widget w;
XtPointer closure;
XtPointer call_data;
{
  struct SearchAndReplace * search = (struct SearchAndReplace *) closure;

  SetSearchLabels(search, "Search", "", FALSE);
  XtPopdown( search->search_popup );
}

/*	Function Name: SearchButton
 *	Description: Performs a search when the button is clicked.
 *	Arguments: w - *** NOT USED **.
 *                 closure - a pointer to the search info.
 *                 call_data - *** NOT USED ***.
 *	Returns:
 */

/* ARGSUSED */
static void
SearchButton(w, closure, call_data)
Widget w;
XtPointer closure;
XtPointer call_data;
{
  (void) DoSearch( (struct SearchAndReplace *) closure );
}

/*	Function Name: _XawTextSearch
 *	Description: Action routine that can be bound to the text widget
 *                   it will popup the search dialog box.
 *	Arguments:   w - the text widget.
 *                   event - X Event (used to get x and y location).
 *                   params, num_params - the parameter list.
 *	Returns:     none.
 *
 * NOTE:
 *
 * The parameter list contains one or two entries that may be the following.
 *
 * First Entry:   The first entry is the direction to search by default.
 *                This argument must be specified and may have a value of
 *                "left" or "right".
 *
 * Second Entry:  This entry is optional and contains the value of the default
 *                string to search for.
 */

#define SEARCH_HEADER ("Text Widget - Search():")

void
_XawTextSearch(w, event, params, num_params)
Widget w;
XEvent *event;
String * params;
Cardinal * num_params;
{
  TextWidget ctx = (TextWidget)w;
  XawTextScanDirection dir;
  char * ptr, buf[BUFSIZ];
  XawTextEditType edit_mode;
  Arg args[1];

#ifdef notdef
  if (ctx->text.source->Search == NULL) {
      XBell(XtDisplay(w), 0);
      return;
  }
#endif

  if ( (*num_params < 1) || (*num_params > 2) ) {
    sprintf(buf, "%s %s\n%s", SEARCH_HEADER, "This action must have only",
	    "one or two parameters");
    XtAppWarning(XtWidgetToApplicationContext(w), buf);
    return;
  }
  else if (*num_params == 1)
    ptr = "";
  else
    ptr = params[1];

  switch(params[0][0]) {
  case 'b':			/* Left. */
  case 'B':
    dir = XawsdLeft;
    break;
  case 'f':			/* Right. */
  case 'F':
    dir = XawsdRight;
    break;
  default:
    sprintf(buf, "%s %s\n%s", SEARCH_HEADER, "The first parameter must be",
	    "Either 'backward' or 'forward'");
    XtAppWarning(XtWidgetToApplicationContext(w), buf);
    return;
  }

  if (ctx->text.search== NULL) {
    ctx->text.search = XtNew(struct SearchAndReplace);
    ctx->text.search->search_popup = CreateDialog(w, ptr, "search",
						  AddSearchChildren);
    XtRealizeWidget(ctx->text.search->search_popup);
    SetWMProtocolTranslations(ctx->text.search->search_popup);
  }
  else if (*num_params > 1) {
    XtVaSetValues(ctx->text.search->search_text, XtNstring, ptr, NULL);
  }

  XtSetArg(args[0], XtNeditType,&edit_mode);
  XtGetValues(ctx->text.source, args, ONE);

  InitializeSearchWidget(ctx->text.search, dir, (edit_mode == XawtextEdit));

  CenterWidgetOnPoint(ctx->text.search->search_popup, event);
  XtPopup(ctx->text.search->search_popup, XtGrabNone);
}

/*	Function Name: InitializeSearchWidget
 *	Description: This function initializes the search widget and
 *                   is called each time the search widget is poped up.
 *	Arguments: search - the search widget structure.
 *                 dir - direction to search.
 *                 replace_active - state of the sensitivity for the
 *                                  replace button.
 *	Returns: none.
 */

static void
InitializeSearchWidget(struct SearchAndReplace *search,
  XawTextScanDirection dir, Boolean replace_active)
{
replace_active = replace_active; /* PH - shuts compilers up */

  switch (dir) {
  case XawsdLeft:
    SetResource(search->left_toggle, XtNstate, (XtArgVal) TRUE);
    break;
  case XawsdRight:
    SetResource(search->right_toggle, XtNstate, (XtArgVal) TRUE);
    break;
  default:
    break;
  }
}

/*	Function Name: AddSearchChildren
 *	Description: Adds all children to the Search Dialog Widget.
 *	Arguments: form - the form widget for the search widget.
 *                 ptr - a pointer to the initial string for the Text Widget.
 *                 tw - the main text widget.
 *	Returns: none.
 */

static void
AddSearchChildren(form, ptr, tw)
Widget form, tw;
char * ptr;
{
  Arg args[10];
  Cardinal num_args;
  Widget cancel, search_button, s_label, s_text;
  XtTranslations trans;
  struct SearchAndReplace * search = ((TextWidget) tw)->text.search;

  num_args = 0;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNresizable, TRUE ); num_args++;
  XtSetArg(args[num_args], XtNborderWidth, 0 ); num_args++;
  search->label1 = XtCreateManagedWidget("label1", labelWidgetClass,
					 form, args, num_args);

 /*
 * We need to add R_OFFSET to the radio_data, because the value zero (0)
 * has special meaning.
 */

  num_args = 0;
  XtSetArg(args[num_args], XtNlabel, "Backward"); num_args++;
  XtSetArg(args[num_args], XtNfromVert, search->label1); num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNradioData, (caddr_t) XawsdLeft + R_OFFSET);
  num_args++;
  search->left_toggle = XtCreateManagedWidget("backwards", toggleWidgetClass,
					      form, args, num_args);

  num_args = 0;
  XtSetArg(args[num_args], XtNlabel, "Forward"); num_args++;
  XtSetArg(args[num_args], XtNfromVert, search->label1); num_args++;
  XtSetArg(args[num_args], XtNfromHoriz, search->left_toggle); num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNradioGroup, search->left_toggle); num_args++;
  XtSetArg(args[num_args], XtNradioData, (caddr_t) XawsdRight + R_OFFSET);
  num_args++;
  search->right_toggle = XtCreateManagedWidget("forwards", toggleWidgetClass,
					       form, args, num_args);

  {
    XtTranslations radio_translations;

    radio_translations = XtParseTranslationTable(radio_trans_string);
    XtOverrideTranslations(search->left_toggle, radio_translations);
    XtOverrideTranslations(search->right_toggle, radio_translations);
  }

  num_args = 0;
  XtSetArg(args[num_args], XtNfromVert, search->left_toggle); num_args++;
  XtSetArg(args[num_args], XtNlabel, "Search for:  ");num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNborderWidth, 0 ); num_args++;
  s_label = XtCreateManagedWidget("searchLabel", labelWidgetClass,
				  form, args, num_args);

  num_args = 0;
  XtSetArg(args[num_args], XtNfromVert, search->left_toggle); num_args++;
  XtSetArg(args[num_args], XtNfromHoriz, s_label); num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainRight); num_args++;
  XtSetArg(args[num_args], XtNeditType, XawtextEdit); num_args++;
  XtSetArg(args[num_args], XtNresizable, TRUE); num_args++;
  XtSetArg(args[num_args], XtNresize, XawtextResizeWidth); num_args++;
  XtSetArg(args[num_args], XtNstring, ptr); num_args++;
  s_text = XtCreateManagedWidget("searchText", asciiTextWidgetClass, form,
				 args, num_args);
  search->search_text = s_text;

  num_args = 0;
  XtSetArg(args[num_args], XtNlabel, "Search"); num_args++;
  XtSetArg(args[num_args], XtNfromVert, s_text); num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  search_button = XtCreateManagedWidget("search", commandWidgetClass, form,
					args, num_args);

  num_args = 0;
  XtSetArg(args[num_args], XtNlabel, "Cancel"); num_args++;
  XtSetArg(args[num_args], XtNfromVert, s_text); num_args++;
  XtSetArg(args[num_args], XtNfromHoriz, search_button); num_args++;
  XtSetArg(args[num_args], XtNleft, XtChainLeft); num_args++;
  XtSetArg(args[num_args], XtNright, XtChainLeft); num_args++;
  cancel = XtCreateManagedWidget(DISMISS_NAME, commandWidgetClass, form,
				 args, num_args);

  XtAddCallback(search_button, XtNcallback, SearchButton, (XtPointer) search);
  XtAddCallback(cancel, XtNcallback, PopdownSearch, (XtPointer) search);

/*
 * Initialize the text entry fields.
 */

  SetSearchLabels(search, "Search", "", FALSE);
  XtSetKeyboardFocus(form, search->search_text);

/*
 * Bind Extra translations.
 */

  trans = XtParseTranslationTable(search_text_trans);
  XtOverrideTranslations(search->search_text, trans);
}

/*	Function Name: DoSearch
 *	Description: Performs a search.
 *	Arguments: search - the search structure.
 *	Returns: TRUE if successful.
 */

/* ARGSUSED */
static Boolean
DoSearch(search)
struct SearchAndReplace * search;
{
  char msg[BUFSIZ];
  Widget tw = XtParent(search->search_popup);
  XawTextPosition pos;
  XawTextScanDirection dir;
  XawTextBlock text;

  text.ptr = GetString(search->search_text);
  text.length = strlen(text.ptr);
  text.firstPos = 0;
  text.format = FMT8BIT;

  dir = (XawTextScanDirection) ((long)XawToggleGetCurrent(search->left_toggle) -
				R_OFFSET);

  pos = XawTextSearch( tw, dir, &text);

  if (pos == XawTextSearchError)
    sprintf( msg, "Could not find string '%s'.", text.ptr);
  else {
    if (dir == XawsdRight)
      XawTextSetInsertionPoint( tw, pos + text.length);
    else
      XawTextSetInsertionPoint( tw, pos);

    XawTextSetSelection( tw, pos, pos + text.length);
    search->selection_changed = FALSE; /* selection is good. */
    return(TRUE);
  }

  XawTextUnsetSelection(tw);
  SetSearchLabels(search, msg, "", TRUE);
  return(FALSE);
}


/*	Function Name: SetSearchLabels
 *	Description: Sets both the search labels, and also rings the bell
 *  HACKED: Only one label needed now
 *	Arguments: search - the search structure.
 *                 msg1, msg2 - message to put in each search label.
 *                 bell - if TRUE then ring bell.
 *	Returns: none.
 */

static void
SetSearchLabels(struct SearchAndReplace *search, String msg1, String msg2,
  Boolean bell)
{
msg2 = msg2; /* PH - shuts compilers up */
  (void) SetResource( search->label1, XtNlabel, (XtArgVal) msg1);
  /* (void) SetResource( search->label2, XtNlabel, (XtArgVal) msg2); */
  if (bell)
    XBell(XtDisplay(search->search_popup), 0);
}

/************************************************************
 *
 * This section of the file contains utility routines used by
 * other functions in this file.
 *
 ************************************************************/


/*	Function Name: SetResource
 *	Description: Sets a resource in a widget
 *	Arguments: w - the widget.
 *                 res_name - name of the resource.
 *                 value - the value of the resource.
 *	Returns: none.
 */

static void
SetResource(w, res_name, value)
Widget w;
char * res_name;
XtArgVal value;
{
  Arg args[1];

  XtSetArg(args[0], res_name, value);
  XtSetValues( w, args, ONE );
}

/*	Function Name: GetString
 *	Description:   Gets the value for the string in the popup.
 *	Arguments:     text - the text widget whose string we will get.
 *	Returns:       the string.
 */

static String
GetString(text)
Widget text;
{
  String string;
  Arg args[1];

  XtSetArg( args[0], XtNstring, &string );
  XtGetValues( text, args, ONE );
  return(string);
}

/*	Function Name: CenterWidgetOnPoint.
 *	Description: Centers a shell widget on a point relative to
 *                   the root window.
 *	Arguments: w - the shell widget.
 *                 event - event containing the location of the point
 *	Returns: none.
 *
 * NOTE: The widget is not allowed to go off the screen.
 */

static void
CenterWidgetOnPoint(w, event)
Widget w;
XEvent *event;
{
  Arg args[3];
  Cardinal num_args;
  Dimension width, height, b_width;
  Position x=0, y=0, max_x, max_y;

  if (event != NULL) {
    switch (event->type) {
    case ButtonPress:
    case ButtonRelease:
      x = event->xbutton.x_root;
      y = event->xbutton.y_root;
      break;
    case KeyPress:
    case KeyRelease:
      x = event->xkey.x_root;
      y = event->xkey.y_root;
      break;
    default:
      return;
    }
  }

  num_args = 0;
  XtSetArg(args[num_args], XtNwidth, &width); num_args++;
  XtSetArg(args[num_args], XtNheight, &height); num_args++;
  XtSetArg(args[num_args], XtNborderWidth, &b_width); num_args++;
  XtGetValues(w, args, num_args);

  width += 2 * b_width;
  height += 2 * b_width;

  x -= ( (Position) width/2 );
  if (x < 0) x = 0;
  if ( x > (max_x = (Position) (XtScreen(w)->width - width)) ) x = max_x;

  y -= ( (Position) height/2 );
  if (y < 0) y = 0;
  if ( y > (max_y = (Position) (XtScreen(w)->height - height)) ) y = max_y;

  num_args = 0;
  XtSetArg(args[num_args], XtNx, x); num_args++;
  XtSetArg(args[num_args], XtNy, y); num_args++;
  XtSetValues(w, args, num_args);
}

/*	Function Name: CreateDialog
 *	Description: Actually creates a dialog.
 *	Arguments: parent - the parent of the dialog - the main text widget.
 *                 ptr - initial_string for the dialog.
 *                 name - name of the dialog.
 *                 func - function to create the children of the dialog.
 *	Returns: the popup shell of the dialog.
 *
 * NOTE:
 *
 * The function argument is passed the following arguments.
 *
 * form - the from widget that is the dialog.
 * ptr - the initial string for the dialog's text widget.
 * parent - the parent of the dialog - the main text widget.
 */

static Widget
CreateDialog(parent, ptr, name, func)
Widget parent;
String ptr, name;
void (*func)();
{
  Widget popup, form;
  Arg args[5];
  Cardinal num_args;

  num_args = 0;
  XtSetArg(args[num_args], XtNiconName, name); num_args++;
  XtSetArg(args[num_args], XtNgeometry, NULL); num_args++;
  XtSetArg(args[num_args], XtNallowShellResize, TRUE); num_args++;
  XtSetArg(args[num_args], XtNtransientFor, GetShell(parent)); num_args++;
  popup = XtCreatePopupShell(name, transientShellWidgetClass,
			     parent, args, num_args);

  form = XtCreateManagedWidget(FORM_NAME, formWidgetClass, popup,
			       NULL, ZERO);

  (*func) (form, ptr, parent);
  return(popup);
}

 /*	Function Name: GetShell
  *	Description: Walks up the widget hierarchy to find the
  *		nearest shell widget.
  *	Arguments: w - the widget whose parent shell should be returned.
  *	Returns: The shell widget among the ancestors of w that is the
  *		fewest levels up in the widget hierarchy.
  */

static Widget
GetShell(w)
Widget w;
{
    while ((w != NULL) && !XtIsShell(w))
	w = XtParent(w);

    return (w);
}

/* Add proper prototype to keep IRIX 6 compiler happy. PH */

static Boolean InParams(String, String *, Cardinal);

static Boolean InParams(str, p, n)
    String str;
    String *p;
    Cardinal n;
{
    int i;
    for (i=0; i < n; p++, i++)
	if (! XmuCompareISOLatin1(*p, str)) return True;
    return False;
}

static char *WM_DELETE_WINDOW = "WM_DELETE_WINDOW";

static void WMProtocols(w, event, params, num_params)
    Widget w;		/* popup shell */
    XEvent *event;
    String *params;
    Cardinal *num_params;
{
    Atom wm_delete_window;
    Atom wm_protocols;

    wm_delete_window = XInternAtom(XtDisplay(w), WM_DELETE_WINDOW, True);
    wm_protocols = XInternAtom(XtDisplay(w), "WM_PROTOCOLS", True);

    /* Respond to a recognized WM protocol request iff
     * event type is ClientMessage and no parameters are passed, or
     * event type is ClientMessage and event data is matched to parameters, or
     * event type isn't ClientMessage and parameters make a request.
     */
#define DO_DELETE_WINDOW InParams(WM_DELETE_WINDOW, params, *num_params)

    if ((event->type == ClientMessage &&
	 event->xclient.message_type == wm_protocols &&
	 event->xclient.data.l[0] == wm_delete_window &&
	 (*num_params == 0 || DO_DELETE_WINDOW))
	||
	(event->type != ClientMessage && DO_DELETE_WINDOW)) {

#undef DO_DELETE_WINDOW

	Widget cancel;
	char descendant[DISMISS_NAME_LEN + 2];
	sprintf(descendant, "*%s", DISMISS_NAME);
	cancel = XtNameToWidget(w, descendant);
	if (cancel) XtCallCallbacks(cancel, XtNcallback, (XtPointer)NULL);
    }
}

static void SetWMProtocolTranslations(w)
    Widget	w;	/* realized popup shell */
{
    int i;
    XtAppContext app_context;
    Atom wm_delete_window;
    static XtTranslations compiled_table;	/* initially 0 */
    static XtAppContext *app_context_list;	/* initially 0 */
    static Cardinal list_size;			/* initially 0 */

    app_context = XtWidgetToApplicationContext(w);

    /* parse translation table once */
    if (! compiled_table) compiled_table = XtParseTranslationTable
	("<Message>WM_PROTOCOLS: XawWMProtocols()\n");

    /* add actions once per application context */
    for (i=0; i < list_size && app_context_list[i] != app_context; i++) ;
    if (i == list_size) {
	XtActionsRec actions[1];
	actions[0].string = "XawWMProtocols";
	actions[0].proc = WMProtocols;
	list_size++;
	app_context_list = (XtAppContext *) XtRealloc
	    ((char *)app_context_list, list_size * sizeof(XtAppContext));
	XtAppAddActions(app_context, actions, 1);
	app_context_list[i] = app_context;
    }

    /* establish communication between the window manager and each shell */
    XtAugmentTranslations(w, compiled_table);
    wm_delete_window = XInternAtom(XtDisplay(w), WM_DELETE_WINDOW, False);
    (void) XSetWMProtocols(XtDisplay(w), XtWindow(w), &wm_delete_window, 1);
}
