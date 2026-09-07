# T5b Profile Report — `run_regex_scan` Hot Path

- iterations: **1000**
- rules loaded: **22**
- compiled engine size: **22** patterns
- matches: **1000**
- payload: synthetic HTTP request with SQL injection + UNION SELECT

## Top cumulative-time hotspots

```
         10001 function calls in 0.004 seconds

   Ordered by: cumulative time

   ncalls  tottime  percall  cumtime  percall filename:lineno(function)
     1000    0.002    0.000    0.004    0.000 D:\NIDs_Windows\brain\windows_brain.py:187(run_regex_scan)
     7000    0.001    0.000    0.001    0.000 {method 'get' of 'dict' objects}
     1000    0.001    0.000    0.001    0.000 {method 'search' of 're.Pattern' objects}
     1000    0.000    0.000    0.000    0.000 {method 'upper' of 'str' objects}
        1    0.000    0.000    0.000    0.000 {method 'disable' of '_lsprof.Profiler' objects}


```

## Conclusion

This profile is the AC1 evidence for T5b: a measurement-driven identification of the real Python hotspot. See `test_cython_profile.py` for the locked-in assertion that the hotspot is where we expected it (the `re.search` loop in `run_regex_scan`), and `test_cython_regression.py` for the locked-in speedup.
