from django.shortcuts import render, redirect
from django.contrib import messages, auth
from django.core.validators import validate_email
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

def login(request):
  if request.method != 'POST':
    return render(request, 'accounts/login.html')
  
  usuario = request.POST.get('usuario')
  senha = request.POST.get('senha')
  user = auth.authenticate(request, username=usuario, password=senha)

  if not user:
    messages.error(request, 'User or Password invalids')
    return render(request, 'accounts/login.html')
  else:
    auth.login(request, user)
    messages.success(request, 'Logged with sucess')
    return redirect('dashboard')


def logout(request):
  auth.logout(request)
  return redirect('index')

def register(request):
  if request.method != 'POST':
    return render(request, 'accounts/register.html')

  nome = request.POST.get('nome')
  sobrenome = request.POST.get('sobrenome')
  email = request.POST.get('email')
  usuario = request.POST.get('usuario')
  senha = request.POST.get('senha')
  repetir_senha = request.POST.get('repetir-senha')

  if not nome or not sobrenome or not email or not usuario or not senha or not repetir_senha:
    messages.error(request, 'Anyone filds can be empty.')
    return render(request, 'accounts/register.html')
  try:
    validate_email(email)
  except:
    messages.error(request, 'Email invalid.')
    return render(request, 'accounts/register.html')

  if len(senha) < 6:
    messages.error(request, 'Password need has 6 characters or more.')
    return render(request, 'accounts/register.html')

  if len(usuario) < 6:
    messages.error(request, 'User need has 6 characters or more.')
    return render(request, 'accounts/register.html')

  if senha != repetir_senha:
    messages.error(request, 'passwords must be the same.')
    return render(request, 'accounts/register.html')

  if User.objects.filter(username=usuario).exists():
    messages.error(request, 'User already exists.')
    return render(request, 'accounts/register.html')
  
  if User.objects.filter(email=email).exists():
    messages.error(request, 'Email already exists')
    return render(request, 'accounts/register.html')

  messages.success(request, 'Registed success, perform login')
  user = User.objects.create(username=usuario, email=email, password=senha, first_name=nome, last_name=sobrenome)
  user.save()
  return redirect('login')


@login_required(redirect_field_name='login')
def dashboard(request):
  return render(request, 'accounts/dashboard.html')


