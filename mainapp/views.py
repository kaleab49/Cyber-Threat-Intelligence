from django.http import HttpResponse


def home(request):
    return HttpResponse("<h1>Please Head to /api</h1>")

