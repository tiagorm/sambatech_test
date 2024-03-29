from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'sambatech_test.views.home', name='home'),
    # url(r'^sambatech_test/', include('sambatech_test.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    # url(r'^admin/', include(admin.site.urls)),
    (r'^file_uploaded/', 'sambatech_test.views.file_uploaded'),
    (r'^convert/', 'sambatech_test.views.convert'),
    (r'^play_video/', 'sambatech_test.views.play_video'),
    (r'^$', 'sambatech_test.views.index'),
)
