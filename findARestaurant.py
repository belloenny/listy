# -*- coding: utf-8 -*-
import json
import httplib2

import sys
import codecs
sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

foursquare_client_id = "3DJQTVJPRQAJGCLCKVFM4AZCT4MMXIT2ITZ54XU1O3MXVNXF"
foursquare_client_secret = "0LTLRU4DLZQ1EIL0HHSHF2HPWBCXKPL22CRRH2ZERTC513OX"
google_api_key = "AIzaSyAG6FV17jXVfc2d3Gd5VwjFh-lTjlOx3hY"

def getGeocodeLocation(inputString):
    locationString = inputString.replace(" ", "+")
    url = ('https://maps.googleapis.com/maps/api/geocode/json?address=%s&key+%s'% (locationString,google_api_key))
    print("----->", url)
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content)
    lat = result['results'][0]['geometry']['location']['lat']
    longitude = result['results'][0]['geometry']['location']['lng']
    return (lat, longitude)

def findARestaurant(mealType,location):
    #1. Use getGeocodeLocation to get the latitude and longitude coordinates of the location string.
    coordinates = getGeocodeLocation(location)
    #2.  Use foursquare API to find a nearby restaurant with the latitude, longitude, and mealType strings.
    #HINT: format for url will be something like https://api.foursquare.com/v2/venues/search?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&v=20130815&ll=40.7,-74&query=sushi
    
    url = ('https://api.foursquare.com/v2/venues/search?&client_id=%s&client_secret=%s&v=20170818&ll=%s,%s&query=%s'% (foursquare_client_id,foursquare_client_secret,coordinates[0],coordinates[1],mealType))
    h = httplib2.Http()
    response, content = h.request(url, 'GET')
    result = json.loads(content)
    #3. Grab the first restaurant
    if result['response']['venues']:
        restaurant = result['response']['venues'][0]
        restaurant_address = restaurant['location']['formattedAddress']
        address = ""
        for i in restaurant_address:
            address += i + " "
        restaurant_address = address
        restaurant_info = {
            'name': restaurant['name'],
            'address' : restaurant_address}
        #4. Get a  300x300 picture of the restaurant using the venue_id (you can change this by altering the 300x300 value in the URL or replacing it with 'orginal' to get the original picture
        url = ('https://api.foursquare.com/v2/venues/%s/photos?&limit=1&client_id=%s&client_secret=%s&v=20170818'% (restaurant['id'],foursquare_client_id,foursquare_client_secret))
        photo_response, photo_content = h.request(url, "GET")
        photo_result = json.loads(photo_content)

        if photo_result['response']['photos']['count'] > 0:
            #5. Grab the first image
            photo = photo_result['response']['photos']['items'][0]
            url = photo['prefix'] + '300x300' + photo['suffix']
        else:
            #6. If no image is available, insert default a image url
            url = 'http://locahost:6000/imgs/default.jpg'
        #7. Return a dictionary containing the restaurant name, address, and image url 
        restaurant_info['image_url'] = url
        print ("Restaurant Name:", restaurant_info['name'])
        print ("Restaurant Address:", restaurant_info['address'])
        print ("Image: %s \n" % restaurant_info['image_url'])
        return restaurant_info
    else:
        print ("No Restaurants Found for %s" % location)
        return "No Restaurants Found"
        
if __name__ == '__main__':
    findARestaurant("Pizza", "Tokyo, Japan")
    findARestaurant("Tacos", "Jakarta, Indonesia")
    findARestaurant("Tapas", "Maputo, Mozambique")
    findARestaurant("Falafel", "Cairo, Egypt")
    findARestaurant("Spaghetti", "New Delhi, India")
    findARestaurant("Cappuccino", "Geneva, Switzerland")
    findARestaurant("Sushi", "Los Angeles, California")
    findARestaurant("Steak", "La Paz, Bolivia")
    findARestaurant("Gyros", "Sydney Australia")