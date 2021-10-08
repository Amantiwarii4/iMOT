import binascii
import string
from random import random
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.parsers import JSONParser

from .serializers import GarageSerializer, MyTokenObtainPairSerializer, UserSerializer, AdminSerializer, \
    UseradminSerializer
from .models import Garages
from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password
import base64
from django.utils.translation import ugettext_lazy as _
from rest_framework import status
from rest_framework.authentication import get_authorization_header
from rest_framework import HTTP_HEADER_ENCODING


def authorized(request):
    auth = get_authorization_header(request).split()
    if not auth or auth[0].lower() != b'basic':
        msg = _("Not basic authentication.")
        result = {'status': False, 'message': msg}
        return result
    if len(auth) == 1:
        msg = _('Invalid basic header. No credentials provided.')
        result = {'status': False, 'message': msg}
        return result
    elif len(auth) > 2:
        msg = _('Invalid basic header. Credentials string should not contain spaces.')
        result = {'status': False, 'message': msg}
        return result
    try:
        auth_parts = base64.b64decode(auth[1]).decode(HTTP_HEADER_ENCODING).partition(':')
    except (TypeError, UnicodeDecodeError, binascii.Error):
        msg = _('Invalid basic header. Credentials not correctly base64 encoded.')
        result = {'status': False, 'message': msg}
        return result

    userid, password = auth_parts[0], auth_parts[2]
    # Your auth table specific codes
    if 'imot' == userid and '026866326a9d1d2b23226e4e8929192g' == password:  # my dummy code
        result = {'status': True, 'message': ""}
        return result
    else:
        msg = _('User not found.')
        result = {'status': False, 'message': msg}
        return result


# ------------------------GARAGE_APIS----------------------------------
@csrf_exempt
def add_garage(request):
    result = authorized(request)
    if result['status'] == True:
        try:
            if request.method == 'POST':
                name = request.POST.get('name')
                location = request.POST.get('location')
                garage_detail = request.POST.get('garage_detail')
                additional_services = request.POST.get('additional_services')
                phone = request.POST.get('phone')
                timing = request.POSt.get('timing')
                image = request.POST.FILES('image')
                user = User.objects.get(id=request.POST.FILES('user_id'))
                Garages.objects.create(user=user, name=name, location=location, garage_detail=garage_detail,
                                       additional_services=additional_services
                                       , phone=phone, timing=timing, image=image)
                return JsonResponse({'Status': True, 'Message': 'Garage added successfully!!'})
        except Exception as e:
            return JsonResponse({'Status': False, 'Exception': str(e)})
    return JsonResponse({'Status': False, 'Message': 'Unauthorised User'})


@csrf_exempt
def edit_garage(request):
    result = authorized(request)
    if result['status'] == True:
        try:
            if request.method == 'POST':
                id = request.POST.get('id')
                name = request.POST.get('name')
                location = request.POST.get('location')
                garage_detail = request.POST.get('garage_detail')
                additional_services = request.POST.get('additional_services')
                phone = request.POST.get('phone')
                timing = request.POSt.get('timing')
                image = request.POST.FILES('image')
                user = User.objects.get(id=request.POST.FILES('user_id'))
                Garages.objects.fileter(id=id).updte(user=user, name=name, location=location,
                                                     garage_detail=garage_detail,
                                                     additional_services=additional_services
                                                     , phone=phone, timing=timing, image=image)
                return JsonResponse({'Status': True, 'Message': 'Garage edited successfully!!'})
        except Exception as e:
            return JsonResponse({'Status': False, 'Exception': str(e)})
    return JsonResponse({'Status': False, 'Message': 'Unauthorised User'})


@csrf_exempt
def show_garage(request):
    result = authorized(request)
    if result['status'] == True:
        if request.method == 'POST':
            garages = Garages.objects.all().order_by('-id')
            garages_serializer = GarageSerializer(garages, many=True)
            return JsonResponse(
                {'Status': True, 'message': 'Banner listed successfully!', 'data': garages_serializer.data}, safe=False)
    return JsonResponse({'Status': False, 'Message': 'Unauthorised User'})


@csrf_exempt
def delete_garage(request):
    result = authorized(request)
    if result['status'] == True:
        if request.method == 'POST':
            pk = request.POST.get('id')
            try:
                garages = Garages.objects.get(id=pk)
                garages.delete()
                return JsonResponse({'Status': True, 'message': 'Product deleted successfully!'})
            except:
                return JsonResponse({'Status': False, 'message': 'Id not found!'})
    return JsonResponse({"message": "Unauthorised User", })


# =====================USER+APIS==================================
@csrf_exempt
def user_login(request):
    result = authorized(request)
    if result['status'] == True:
        tok = MyTokenObtainPairSerializer()  # object to get user token
        if request.method == 'POST':
            phone = request.POST.get('phone')
            block = User.objects.filter(phone=phone).values('is_block')
            try:
                users = User.objects.get(phone=phone)
                id = User.objects.filter(phone=phone).values('id')
                block = User.objects.filter(phone=phone).values('is_block')
                block1 = block[0]
            except:
                users = None
            if users is not None and block1['is_block'] == False:
                users_serializer = UserSerializer(users)
                token = tok.get_token(users)
                otp = random.randint(1111, 9999)
                id1 = id[0]
                otp_entry = User.objects.filter(id=id1['id']).update(otp=otp)
                return JsonResponse(
                    {'message': 'User logged in successfully!', 'data': users_serializer.data,
                     'otp': otp})
            else:
                S = 10
                username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=S))
                otp = random.randint(1111, 9999)
                try:
                    user = User.objects.create_user(username=str(username),
                                                    password="herk12354312",
                                                    phone=phone,
                                                    otp=otp,
                                                    )
                    user.save()
                    id1 = user.id
                    users = User.objects.get(id=id1)
                    token = tok.get_token(users)
                    stoken = str(token)
                    users_serializer = UserSerializer(users)
                    return JsonResponse(
                        {'status': True, 'message': 'User logged in successfully!', 'data': users_serializer.data,
                         'otp': otp})
                except:
                    return JsonResponse(
                        {'status': True, 'message': 'You have been blocked by admin', })
    return JsonResponse({"message": "Unauthorised User", })


@csrf_exempt
def auth_otp(request):
    result = authorized(request)
    if result['status'] == True:
        tok = MyTokenObtainPairSerializer()  # object to get user token
        if request.method == 'POST':
            id = request.POST.get('id')
            otp = request.POST.get('otp')
            users = User.objects.get(id=id)
            otp_stored = User.objects.filter(id=id).values('otp')[0]
            print(type(otp))
            if otp == str(otp_stored['otp']):
                users_serializer = UserSerializer(users)
                token = tok.get_token(users)
                stoken = str(token)
                return JsonResponse(
                    {'Status': True, 'data': users_serializer.data, 'token': stoken,
                     'otp': otp})
            else:
                users_serializer = UserSerializer(users)
                return JsonResponse(
                    {'Status': False, 'data': users_serializer.data,
                     })
    return JsonResponse({"message": "Unauthorised User", })


@api_view(['POST'])
@csrf_exempt
def admin_login(request, format=json):
    # result = authorized(request)
    # if result['status'] == True:
    parser_classes = [JSONParser]
    tok = MyTokenObtainPairSerializer()
    content = request.data
    email = content['email']
    # print(email)
    # exit()
    if request.method == 'POST':
        email = content['email']
        password = content['password']
        try:
            password1 = User.objects.filter(email=email).values('password')[0]
            users = User.objects.get(email=email)
        except:
            password1 = {'password': ''}
        if check_password(password, password1['password']) == True:
            token = tok.get_token(users)
            stoken = str(token)
            user_token = User.objects.filter(email=email).update(token=stoken)
            users_serializer = AdminSerializer(users)
            return JsonResponse(
                {'Status': True, 'Message': 'User logged in successfully!', 'Data': users_serializer.data,
                 'Token': stoken,
                 })
        else:
            return JsonResponse(
                {'Status': False, 'Message': 'Wrong Credentials!',
                 })
    # return JsonResponse({"message": "Unauthorised User", })


@csrf_exempt
def add_user(request):
    result = authorized(request)
    if result['status'] == True:
        try:
            if request.method == 'POST':
                S = 10
                username = ''.join(random.choices(string.ascii_uppercase + string.digits, k=S))
                first_name = request.POST.get('first_name')
                last_name = request.POST.get('last_name')
                email = request.POST.get('email')
                password = request.POST.get('password')
                User.objects.create(username=username, first_name=first_name, last_name=last_name, email=email,
                                    password=password)
                return JsonResponse({'Status': True, 'Message': 'User created successful!!'})
        except Exception as e:
            return JsonResponse({'Status': False, 'Exception': str(e)})
    return JsonResponse({'Status': False, 'Message': 'Unauthorised User'})


@csrf_exempt
def user_list(request):
    result = authorized(request)
    if result['status'] == True:
        if request.method == "POST":
            token = request.POST.get('token')
            try:
                # token = request.POST.get('token')
                user = User.objects.get(token=token)
            except:
                user = None
            if user is not None:
                user = User.objects.exclude(is_superuser=1).order_by('-id')
                serializer = UseradminSerializer(user, many=True)
                return JsonResponse(
                    {'status': True, 'message': 'Users Address!', 'data': serializer.data,
                     })
        return JsonResponse({'status': False, 'message': 'Something went wrong!!', })
    return JsonResponse({"message": "Unauthorised User", })

