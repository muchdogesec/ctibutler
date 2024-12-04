
```shell
python3 -m venv ctibutler-venv && \
source ctibutler-venv/bin/activate && \
pip3 install -r requirements.txt
````

## API schema tests

```shell
st run --checks all http://127.0.0.1:8006/api/schema --generation-allow-x00 true
```

