FROM python:3.7
ENV PYTHONUNBUFFERED 1

# Requirements have to be pulled and installed here, otherwise caching won't work
COPY ./requirements /requirements

RUN pip install -r /requirements/production.txt \
    && groupadd -r django \
    && useradd -r -g django django


COPY ./compose/django/prod/start-django.sh /start-django.sh
COPY ./compose/django/prod/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r//' /entrypoint.sh \
    && sed -i 's/\r//' /start-django.sh \
    && chmod +x /entrypoint.sh \
    && chown django /entrypoint.sh \
    && chmod +x /start-django.sh \
    && chown django /start-django.sh


COPY . /app
RUN chown -R django /app
USER django

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
