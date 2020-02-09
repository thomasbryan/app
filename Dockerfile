FROM php:7.2-fpm-stretch
RUN apt-get update && apt-get install -my \
  nginx \
  supervisor
RUN docker-php-ext-install pdo_mysql
COPY default /etc/nginx/sites-enabled/
COPY supervisord.conf /etc/supervisor/conf.d/
COPY index.php /var/www/html/public/
CMD ["/usr/bin/supervisord"]
EXPOSE 80
