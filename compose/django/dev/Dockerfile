FROM python:3.7
ENV PYTHONUNBUFFERED 1

# Requirements have to be pulled and installed here, otherwise caching won't work
COPY ./requirements /requirements
RUN pip install -r /requirements/development.txt

COPY ./compose/django/dev/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r//' /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY ./compose/django/dev/start-django.sh /start-django.sh
RUN sed -i 's/\r//' /start-django.sh
RUN chmod +x /start-django.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
