#!/usr/bin/env python3

import socket
import sys
import json

HOST = "api.openweathermap.org"
PORT = 80

def create_link(city, api_key):
    link = "/data/2.5/weather?q=" + city + "&units=metric" + "&mode=json"
    link = link + "&APPID=" + api_key
    return link

def create_request(city, api_key):
    request = "GET " + create_link(city,api_key) +" HTTP/1.1\r\nHost: api.openweathermap.org\r\n\r\n"
    return request

def main():
    # parsing the input arguments
    if(len(sys.argv) != 5):
        sys.stderr.write("Unsufficient number of arguments\n")
        raise ValueError
    else:
        api_key = sys.argv[2]
        city = sys.argv[4]

    # create request for http
    request = create_request(city, api_key)

    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(request)
    data = (s.recv(4096)).split("\n")
    
    # parse the weather
    weather = json.loads(data[len(data) - 1])
    
    # get the return code
    try:
        return_code = weather['cod']
    except:
        return_code = 400

    # managing return codes
    if(return_code == 200):
        pass
    elif(return_code == 404):
        sys.stderr.write("404: " + city + " not found\n")
        sys.exit()
    elif(return_code == 401):
        sys.stderr.write("401: Invalid API key: " + api_key + "\n")
        sys.exit()
    elif(return_code == 400):
        sys.stderr.write("400: Bad request\n")
        sys.exit()
    else:
        sys.stderr.write(str(return_code) + ": Error\n")
        sys.exit()
    
    # country and city    
    country = weather['sys']['country']
    city = weather['name']
    sys.stdout.write("City: " + city + ", " + country + "\n")

    # weather
    main_weather = weather['weather'][0]['main']
    sys.stdout.write("Weather: " + str(main_weather) + "\n")

    # temperature
    temperature = weather['main']['temp']
    sys.stdout.write("Temperature: " + str(temperature) + " degrees Celcius\n")

    # humidity
    humidity = weather['main']['humidity']
    sys.stdout.write("Humidity: " + str(humidity) + "%\n")

    # pressure
    pressure = weather['main']['pressure']
    sys.stdout.write("Pressure: " + str(pressure) + " hPa\n")

    # wind speed
    wind_speed = weather['wind']['speed']
    sys.stdout.write("Wind speed: " + str(wind_speed) + " m/s\n")

    # wind-deg
    wind_degree = weather['wind']['deg']
    sys.stdout.write("Wind degree: " + str(wind_degree) + "\n")


if __name__ == '__main__':
    main()