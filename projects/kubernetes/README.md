# Kubernetes fuzzers

## api_marshaling_fuzzer
The api_marshaling_fuzzer is created automatically by `autogenerate.py`. The reason that this particular fuzzer is created by a script and not explicitly available is that it is more than 35k lines long. Maintaining such a large fuzzer becomes tedious, when new APIs in Kubernetes get introduced or old ones removed. 
### `autogenerate.py` usage
```bash
cd kubernetes
grep -r ") Marshal()" . > /tmp/grep_result.txt
python3 autogenerate.py --input_file /tmp/grep_result.txt
```
The fuzzer is now available and can be built.
