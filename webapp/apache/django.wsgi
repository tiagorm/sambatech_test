import os
import sys
 
path = '/usr/local/www/sambatech_test/webapp'
if path not in sys.path:
    sys.path.insert(0, path)
 
os.environ['DJANGO_SETTINGS_MODULE'] = 'sambatech_test.settings'
 
import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()
