#!/bin/sh

incdir=`dirname $0`/../../../testprogs/blackbox
. $incdir/subunit.sh

if [ ! -x $BINDIR/tevent_glib_glue_test ] ; then
    # Some machines don't have /bin/true, simulate it
    cat >$BINDIR/tevent_glib_glue_test <<EOF
#!/bin/sh
exit 0
EOF
    chmod +x $BINDIR/tevent_glib_glue_test
fi

failed=0

testit "tevent_glib_glue_test" $VALGRIND $BINDIR/tevent_glib_glue_test ||
	failed=`expr $failed + 1`

testok $0 $failed
