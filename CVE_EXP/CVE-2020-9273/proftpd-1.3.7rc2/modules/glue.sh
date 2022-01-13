#!/bin/sh

TEMPLATE=$srcdir/module_glue.c.tmpl
GLUE=module_glue.c

cp $TEMPLATE $GLUE

for module in $*; do
  module_name=`echo $module | sed -e 's/^mod_\(.*\).o/\1/'`;
  echo "extern module ${module_name}_module;" >>$GLUE
done

echo >>$GLUE
echo "module *static_modules[] = {" >>$GLUE

for module in $*; do
  module_name=`echo $module | sed -e 's/^mod_\(.*\).o/\1/'`;
  echo "  &${module_name}_module," >>$GLUE
done

echo "  NULL" >>$GLUE
echo "};"     >>$GLUE

echo >>$GLUE
echo "module *loaded_modules = NULL;" >>$GLUE
