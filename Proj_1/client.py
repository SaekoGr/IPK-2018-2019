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
    if(len(sys.argv) != 3):
        sys.stderr.write("Unsufficient number of arguments\n")
        sys.exit()

    try:
        api_key = sys.argv[1]
    except:
        sys.exit()

    try:
        city = sys.argv[2]
    except:
        sys.exit()

    # create request for http
    request = create_request(city, api_key)

    # create socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        sys.stderr.write("Failed to create socket\n")
        sys.exit()

    try:
        s.connect((HOST, PORT))
    except:
        sys.stderr.write("Failed to connect\n")
        sys.exit()

    try:
        s.sendall(request)
    except socket.error:
        sys.stderr.write("HTTP request failed")
        sys.exit()

    data = (s.recv(4096)).split("\n")
    
    # parse the weather
    weather = json.loads(data[len(data) - 1])
    
    # get the return code
    try:
        return_code = weather['cod']
    except:
        return_code = 403

    # managing return codes
    if(int(return_code) == 200):
        pass
    elif(int(return_code) == 404):
        sys.stderr.write("404: " + city + " not found\n")
        sys.exit()
    elif(int(return_code) == 401):
        sys.stderr.write("401: Invalid API key: " + api_key + "\n")
        sys.exit()
    elif(int(return_code) == 400):
        sys.stderr.write("400: Bad request\n")
        sys.exit()
    else:
        sys.stderr.write(str(return_code) + ": Error\n")
        sys.exit()
    
    # country and city    
    try:
        country = weather['sys']['country']
        city = weather['name']
        sys.stdout.write("City: " + city + ", " + country + "\n")
    except:
        pass

    # weather
    try:
        main_weather = weather['weather'][0]['main']
        sys.stdout.write("Weather: " + str(main_weather) + "\n")
    except:
        sys.stdout.write("Weather: n/a\n")

    # temperature
    try:
        temperature = weather['main']['temp']
        sys.stdout.write("Temperature: " + str(temperature) + " degrees Celcius\n")
    except:
        sys.stdout.write("Temperature: n/a\n")

    # humidity
    try:
        humidity = weather['main']['humidity']
        sys.stdout.write("Humidity: " + str(humidity) + "%\n")
    except:
        sys.stdout.write("Humidity: n/a\n")

    # pressure
    try:
        pressure = weather['main']['pressure']
        sys.stdout.write("Pressure: " + str(pressure) + " hPa\n")
    except:
        sys.stdout.write("Pressure: n/a\n")

    # wind speed
    try:
        wind_speed = weather['wind']['speed']
        wind_speed = int(wind_speed)*3.6
        sys.stdout.write("Wind speed: " + str(wind_speed) + " km/h\n")
    except:
        sys.stdout.write("Wind speed: n/a km/h\n")
        sys.stdout.write("Wind degree: n/a\n")
        sys.exit() 

    # wind degree
    if(wind_speed == None or wind_speed == 0):
        sys.stdout.write("Wind degree: n/a\n")
    else:
        try:
            wind_degree = weather['wind']['deg']
            sys.stdout.write("Wind degree: " + str(wind_degree) + "\n")
        except:
            sys.stdout.write("Wind degree: n/a\n")


if __name__ == '__main__':
    main()