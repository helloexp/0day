/*************************************************
*                   Exim Monitor                 *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */


#include "em_hdr.h"

/* This module contains functions for handling stripcharts */


/*************************************************
*               Static variables                 *
*************************************************/

static int     queue_first_time = 1;         /* flag for resetting time */
static int     size_first_time = 1;          /* and another */

static int     stripchart_count = 0;         /* count stripcharts created */
static int    *stripchart_delay;             /* vector of delay counts */
static Widget *stripchart_label;             /* vector of label widgets */
static int    *stripchart_last_total;        /* vector of previous values */
static int    *stripchart_max;               /* vector of maxima */
static int    *stripchart_middelay;          /* vector of */
static int    *stripchart_midmax;            /* vector of */
static uschar  **stripchart_name;              /* vector of name strings */
static Widget  stripchart_prev_chart = NULL; /* previously created chart */
static Widget  stripchart_prev_label = NULL; /* previously created label */



/*************************************************
*               Initialize                       *
*************************************************/

void stripchart_init(void)
{
stripchart_delay =      (int *)store_malloc(stripchart_number * sizeof(int));
stripchart_label =   (Widget *)store_malloc(stripchart_number * sizeof(Widget));
stripchart_last_total = (int *)store_malloc(stripchart_number * sizeof(int));
stripchart_max =        (int *)store_malloc(stripchart_number * sizeof(int));
stripchart_middelay =   (int *)store_malloc(stripchart_number * sizeof(int));
stripchart_midmax =     (int *)store_malloc(stripchart_number * sizeof(int));
stripchart_name =     (uschar **)store_malloc(stripchart_number * sizeof(uschar *));
stripchart_total =      (int *)store_malloc(stripchart_number * sizeof(int));
}



/*************************************************
*           Stripchart callback function         *
*************************************************/

/* The client data is the index of the stripchart. We have to play
a little game in order to ensure that the double value is correctly
passed back via the value pointer without the compiler doing an
unwanted cast. */

static void
stripchartAction(Widget w, XtPointer client_data, XtPointer value)
{
double * ptr = (double *)value;
static int thresholds[] =
  {10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 0};
int num = (long)client_data;
int oldmax = 0;
int newmax = 0;
int newvalue = 0;
int i = 0;

/* For the queue stripchart, the value is the current vector value.
We reset the initial delay of 1 second to the normal value. */

if (num == 0)
  {
  newvalue = stripchart_total[0];
  if (queue_first_time)
    {
    xs_SetValues(w, 1, "update", stripchart_update);
    queue_first_time = 0;
    }
  }

/* For the size monitoring stripchart, the value is the percentage
fullness of the partition. A similar fudge to the above is implemented
for the first time. Not all OS have statvfs(); for those that don't this
code is omitted. In fact it should never be obeyed, as we don't allow
size_stripchart to get set in that case. For some OS the old function
and struct name statfs is used; that is handled by a macro. */

else if (size_stripchart != NULL && num == 1)
  {
#ifdef HAVE_STATFS
  struct statvfs statbuf;
  if (statvfs(CS size_stripchart, &statbuf) == 0)
    {
    int used = statbuf.f_blocks - statbuf.f_bfree;
    int max = used + statbuf.f_bavail;
    double fraction = ((double)used) / ((double)max);
    newvalue = (int)((fraction + 0.005) * 100.0);
    }
#endif
  if (size_first_time)
    {
    xs_SetValues(w, 1, "update", stripchart_update);
    size_first_time = 0;
    }
  }

/* For the configured stripcharts, the value to be set is
the difference from last time; save the current total for
next time. */

else
  {
  newvalue = stripchart_total[num] - stripchart_last_total[num];
  stripchart_last_total[num] = stripchart_total[num];
  }

/* Adjust the scale of the stripchart according to the value;
we delay enlarging the scale for a while after the values
reduce. Keep the maximum value while delaying, and reset
down to that. For the size stripchart, the threshold is always
forced to be at least 100. */

while (thresholds[i] > 0)
  {
  int thresh = (size_stripchart != NULL && num == 1)? 100 : thresholds[i++];
  if (newvalue < (double)thresh)
    {
    /* If the current maximum is less than required, or if it is
    greater and we have delayed long enough, adjust the scale. */

    if (stripchart_max[num] < thresh ||
       (stripchart_max[num] > thresh && stripchart_delay[num]++ > 20))
      {
      uschar buffer[128];
      newmax = (thresh > stripchart_midmax[num])?
        thresh : stripchart_midmax[num];
      if (newmax == 10) sprintf(CS buffer, "%s", stripchart_name[num]);
        else sprintf(CS buffer, "%s x%d", stripchart_name[num], newmax/10);
      if (size_stripchart != NULL && num == 1) Ustrcat(buffer, "%");
      xs_SetValues(stripchart_label[num], 1, "label", buffer);
      oldmax = stripchart_max[num];
      stripchart_max[num] = newmax;
      stripchart_midmax[num] = 0;
      stripchart_delay[num] -= stripchart_middelay[num];
      }

    /* Otherwise, if the current maximum is greater than required,
    keep the highest value encountered during the delay, and its
    position so we can adjust the delay when re-scaling. */

    else if (stripchart_max[num] > thresh)
      {
      if (thresh > stripchart_midmax[num])
        {
        stripchart_midmax[num] = thresh;
        stripchart_middelay[num] = stripchart_delay[num];
        }
      }

    /* If the maximum is exactly what we need, reset the delay. */

    if (stripchart_max[num] == thresh) stripchart_delay[num] = 0;
    break;
    }
  }

/* The vanilla Athena stripchart widget does not support change of
scale - it just draws scale lines closer and closer together, which
doesn't work when the number gets very large. However, we can cause
it to change scale quite simply by recomputing all the values and
then calling its repaint routine. I had to nobble the repaint routine
too, to stop it changing scale to anything other than 10. There's
probably a better way to do this, like adding some new resource, but
I'm not a widget programmer and want to get on with the rest of
eximon... */

if (oldmax > 0)
  {
  int i;
  StripChartWidget ww = (StripChartWidget)w;
  ww->strip_chart.max_value = 0;
  for (i = 0; i < (int)ww->strip_chart.interval; i++)
    {
    ww->strip_chart.valuedata[i] =
      (ww->strip_chart.valuedata[i] * oldmax)/newmax;
    if (ww->strip_chart.valuedata[i] > ww->strip_chart.max_value)
      ww->strip_chart.max_value = ww->strip_chart.valuedata[i];
    }
  XClearWindow( XtDisplay(w), XtWindow(w));
  ww->strip_chart.interval = repaint_window(ww, 0, (int)w->core.width);
  }

/* Pass back the new value at the new scale */

*ptr = ((double)newvalue * 10.0)/(double)(stripchart_max[num]);
}



/*************************************************
*            Create one stripchart               *
*************************************************/

/* This function creates two widgets, one being the title and the other being
the stripchart. The client_data values for each stripchart are index into the
stripchart_values vector; each new stripchart just gets the next number. There
is a fudge for the very first stripchart, which is the queue length display,
and for the second if it is a partition size display; its update time is
initially set to 1 second so that it gives an immediate display of the queue.
The first time its callback function is obeyed, the update time gets reset. */

void
create_stripchart(Widget parent, uschar *title)
{
Widget chart;

Widget label = XtCreateManagedWidget("label",
  labelWidgetClass, parent, NULL, 0);

xs_SetValues(label, 10,
  "label",          title,
  "width",          stripchart_width + 2,
  "borderWidth",    0,
  "internalHeight", 0,
  "internalWidth",  0,
  "left",           XawChainLeft,
  "right",          XawChainLeft,
  "top",            XawChainTop,
  "bottom",         XawChainTop,
  XtNfromHoriz,     stripchart_prev_label);

chart = XtCreateManagedWidget("stripchart",
  mystripChartWidgetClass, parent, NULL, 0);

xs_SetValues(chart, 11,
  "jumpScroll", 1,
  "update",     (stripchart_count < stripchart_varstart)? 1:stripchart_update,
  "minScale",   10,
  "width",      stripchart_width,
  "height",     stripchart_height,
  "left",       XawChainLeft,
  "right",      XawChainLeft,
  "top",        XawChainTop,
  "bottom",     XawChainTop,
  XtNfromHoriz, stripchart_prev_chart,
  XtNfromVert,  label);

XtAddCallback(chart, "getValue", stripchartAction,
  (XtPointer)(long)stripchart_count);

stripchart_last_total[stripchart_count] = 0;
stripchart_max[stripchart_count] = 10;
stripchart_midmax[stripchart_count] = 0;
stripchart_name[stripchart_count] = title;
stripchart_prev_label = stripchart_label[stripchart_count] = label;
stripchart_prev_chart = chart;
stripchart_total[stripchart_count] = 0;
stripchart_count++;
}

/* End of em_strip.c */
