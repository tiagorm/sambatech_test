#!/usr/bin/python
# -*- coding: utf-8 -*-
from django.shortcuts import render_to_response
from django.template.context import RequestContext

import settings
import re, time

#Code from http://djangosnippets.org/snippets/1868/

from django import forms
import datetime

import base64
import hmac, sha, simplejson

class S3UploadForm(forms.Form):
    key = forms.CharField(widget = forms.HiddenInput)
    AWSAccessKeyId = forms.CharField(widget = forms.HiddenInput)
    acl = forms.CharField(widget = forms.HiddenInput)
    success_action_redirect = forms.CharField(widget = forms.HiddenInput)
    policy = forms.CharField(widget = forms.HiddenInput)
    signature = forms.CharField(widget = forms.HiddenInput)
    Content_Type = forms.CharField(widget = forms.HiddenInput)
    file = forms.FileField()
    
    def __init__(self, aws_access_key, aws_secret_key, bucket, key,
            expires_after = datetime.timedelta(days = 30),
            acl = 'public-read',
            success_action_redirect = None,
            content_type = '',
            min_size = 0,
            max_size = None
        ):
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.bucket = bucket
        self.key = key
        self.expires_after = expires_after
        self.acl = acl
        self.success_action_redirect = success_action_redirect
        self.content_type = content_type
        self.min_size = min_size
        self.max_size = max_size
        
        policy = base64.b64encode(self.calculate_policy())
        signature = self.sign_policy(policy)
        
        initial = {
            'key': self.key,
            'AWSAccessKeyId': self.aws_access_key,            
            'acl': self.acl,
            'policy': policy,
            'signature': signature,
            'Content-Type': self.content_type,
        }
        if self.success_action_redirect:
            initial['success_action_redirect'] = self.success_action_redirect
        
        super(S3UploadForm, self).__init__(initial = initial)
        
        # We need to manually rename the Content_Type field to Content-Type
        self.fields['Content-Type'] = self.fields['Content_Type']
        del self.fields['Content_Type']
        
        # Don't show success_action_redirect if it's not being used
        if not self.success_action_redirect:
            del self.fields['success_action_redirect']
    
    def as_html(self):
        """
        Use this instead of as_table etc, because S3 requires the file field
        come AFTER the hidden fields, but Django's normal form display methods
        position the visible fields BEFORE the hidden fields.
        """
        html = ''.join(map(unicode, self.hidden_fields()))
        html += unicode(self['file'])
        return html
    
    def as_form_html(self, prefix='', suffix=''):
        html = """
        <form action="%s" method="post" enctype="multipart/form-data">
        <p>%s <input type="submit" value="Upload"></p>
        </form>
        """.strip() % (self.action(), self.as_html())
        return html
    
    def is_multipart(self):
        return True
    
    def action(self):
        return 'http://%s.s3.amazonaws.com/' % self.bucket
    
    def calculate_policy(self):
        conditions = [
            {'bucket': self.bucket},
            {'acl': self.acl},
            ['starts-with', '$key', self.key.replace('${filename}', '')],
            ["starts-with", "$Content-Type", self.content_type],
        ]
        if self.success_action_redirect:
            conditions.append(
                {'success_action_redirect': self.success_action_redirect},
            )
        
        policy_document = {
            "expiration": (
                datetime.datetime.now() + self.expires_after
            ).isoformat().split('.')[0] + 'Z',
            "conditions": conditions,
        }
        return simplejson.dumps(policy_document, indent=2)
    
    def sign_policy(self, policy):
        return base64.b64encode(
            hmac.new(self.aws_secret_key, policy, sha).digest()
        )

#End code from http://djangosnippets.org/snippets/1868/

def index(request):
    
    ip_client = request.META.get("REMOTE_ADDR").replace(".","-")
    
    file_time = datetime.datetime.today()
    file_name = "uploads/"+str(file_time.year)+"-"+str(file_time.month)+"-"+str(file_time.day)+"_"+str(file_time.hour)+"-"+str(file_time.minute)+"-"+str(file_time.second)+"_"+ip_client+"_${filename}"
    
    s3_upload_form = S3UploadForm(
        aws_access_key = settings.AWS_ACCESS_KEY_ID,
        aws_secret_key = settings.AWS_SECRET_ACCESS_KEY,
        bucket = 'tiagorm.sambatech_test',
        key = file_name,
        success_action_redirect = "http://"+request.META.get('HTTP_HOST')+"/file_uploaded/",
        content_type = "video/x-dv"
    )
    
    return render_to_response(
              'index.html',
              {
                #'AWS_ACCESS_KEY_ID': settings.AWS_ACCESS_KEY_ID,
                's3_upload_form': s3_upload_form,
               },
              context_instance=RequestContext(request)
              )

def file_uploaded(request):
    #S3 will add bucket, key and etag parameters to this URL value to inform 
    #your web application of the location and hash value of the uploaded file.
    
    bucket = None
    key = None
    etag = None
    
    if request.method == 'GET':
        if len(request.GET):
            try:
                bucket = request.GET.get('bucket')
            except:
                bucket = "ERROR"
            try:
                key = request.GET.get('key')
            except:
                key = "ERROR"
            try:
                etag = request.GET.get('etag')
            except:
                etag = "ERROR"
    
    return render_to_response(
              'file_uploaded.html',
              {
                'bucket': bucket,
                'key': key,
                'etag': etag,
               },
              context_instance=RequestContext(request)
              )

def convert(request):
    
    bucket = None
    key = None
    etag = None
    error = False
    error_message = ""
    output_video_url = ""
    
    if request.method == 'GET':
        if len(request.GET):
            try:
                bucket = request.GET.get('bucket')
            except:
                error = True
                bucket = "ERROR"
            try:
                key = request.GET.get('key')
            except:
                error = True
                key = "ERROR"
            try:
                etag = request.GET.get('etag')
            except:
                error = True
                etag = "ERROR"
    
            if not error:
                from zencoder import Zencoder
                zen = Zencoder(api_key=settings.ZENCODER_API_KEY)
                
                #creates an encoding job
                RE_FILENAME = re.compile("uploads/(\d+-\d+-\d+_\d+-\d+-\d+_\d+-\d+-\d+-\d+_\S+)\.\S+$")
                fields = re.match(RE_FILENAME,key)
                if fields:
                    input_url = "s3://"+bucket+"/"+key
                    web = {
                           'label': 'web',
                           'url': "s3://"+bucket+"/public_videos/"+fields.group(1)+".mp4",
                           'public': True
                           }
                    outputs = ( web )
                    job = zen.job.create(input_url, outputs=outputs)
                    
                    MAXTRY = 100
                    count = 0
                    while count < MAXTRY:
                        count += 1
                        progress = zen.output.progress(job.body['outputs'][0]['id'])
                        state = progress.body['state']
                        
                        if state == "pending" or state == "waiting" or state == "processing" or state == "queued":
                            time.sleep(3)
                        elif state == "finished":
                            output_video_url = "http://"+bucket+".s3.amazonaws.com/public_videos/"+fields.group(1)+".mp4"
                            break
                        elif state == "failed":
                            error = True
                            error_message = "Falha ao converter arquivo no Zencoder."
                            break
                        elif state == "cancelled":
                            error = True
                            error_message = "Processo de converter arquivo cancelado no Zencoder."
                            break
                        else:
                            error = True
                            error_message = "Erro state <"+str(state)+"> na API do Zencoder."
                            break
                else:
                    error = True
                
                #job = zen.job.create(url)
    return render_to_response(
              'convert.html',
              {
                'bucket': bucket,
                'key': key,
                'etag': etag,
                'output_video_url': output_video_url,
                'error': error,
                'error_message': error_message
               },
              context_instance=RequestContext(request)
              )

def play_video(request):
    
    bucket = None
    key = None
    etag = None
    output_video_url = ""
    error = False
    
    if request.method == 'GET':
        if len(request.GET):
            try:
                bucket = request.GET.get('bucket')
            except:
                error = True
                bucket = "ERROR"
            try:
                key = request.GET.get('key')
            except:
                error = True
                key = "ERROR"
            try:
                etag = request.GET.get('etag')
            except:
                error = True
                etag = "ERROR"
    
            if not error:
                RE_FILENAME = re.compile("uploads/(\d+-\d+-\d+_\d+-\d+-\d+_\d+-\d+-\d+-\d+_\S+)\.\S+$")
                fields = re.match(RE_FILENAME,key)
                if fields:                    
                    output_video_url = "http://"+bucket+".s3.amazonaws.com/public_videos/"+fields.group(1)+".mp4"
                            
                
                #job = zen.job.create(url)
    return render_to_response(
              'play_video.html',
              {
                'bucket': bucket,
                'key': key,
                'etag': etag,
                'output_video_url': output_video_url
               },
              context_instance=RequestContext(request)
              )