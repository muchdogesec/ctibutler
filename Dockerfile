FROM python:3.11
ENV PYTHONUNBUFFERED=1
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY dogesec_commons-0.0.1b2-py3-none-any.whl .
RUN pip install --force-reinstall --no-deps dogesec_commons-0.0.1b2-py3-none-any.whl