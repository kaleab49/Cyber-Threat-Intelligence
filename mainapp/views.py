from django.http import HttpResponse


def home(request):
    return HttpResponse("<h1>Hello World</h1>")


def about(request):
    return HttpResponse("<h2>Someone is here</h2>")
