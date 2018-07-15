import requests
# from app import _celery


# class Weather():
# @_celery.task
def get_weather(self):
    api_key = 'a18ec5023a54c56527886777047bc799'
    city = 'mumbai'

    url = 'http://api.openweathermap.org/data/2.5/weather?q={}&units' +\
        '=imperial&appid={}'

    r = requests.get(url.format(city, api_key)).json()
    print(r)
    weather = {
        'city': city,
        'temperature': r['main']['temp'],
        'description': r['weather'][0]['description'],
        'humidity': r['main']['humidity'],
    }

    print(weather)

    return {"Forecast": weather}
