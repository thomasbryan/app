FROM php:7.2-fpm-stretch
RUN apt-get update && apt-get install -my \
  nginx \
  supervisor
RUN docker-php-ext-install pdo_mysql
COPY zz-docker.conf /usr/local/etc/php-fpm.d/
COPY default /etc/nginx/sites-enabled/
COPY supervisord.conf /etc/supervisor/conf.d/
COPY html /var/www/
RUN chown -R www-data /var/www/html/
CMD ["/usr/bin/supervisord"]
EXPOSE 80
