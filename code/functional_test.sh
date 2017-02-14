#! /bin/bash
expected_resutls="functional_test_results.txt"
obtained_results="functional_test_results_new.txt"
EVAL="./slips functional_test.conf | sort > $obtained_results 2>&1"
eval $EVAL
if cmp -s "$expected_resutls" "$obtained_results"
then
   echo "Tests pass :)"
else
   echo "Tests fail (:"
fi
EVAL="rm $obtained_results"
eval $EVAL
