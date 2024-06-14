import requests

######################tomorrow io#################################################
print("######################tomorrow io #################################################")
# Replace {API_KEY} with your actual tomorrow IO API key
TI_api_key = "2zHJgz9VA4EZOIXpSnJGf2L8WKRssepF"


# Define the API endpoint URL with placeholders
url = f"https://api.tomorrow.io/v4/weather/forecast?location=42.3478,-71.0466&apikey=2zHJgz9VA4EZOIXpSnJGf2L8WKRssepF"
print(url)

# Send a GET request to the API endpoint
response = requests.get(url)

# Check for successful response (status code 200)
if response.status_code == 200:
  # Convert the JSON response to a Python dictionary
  data = response.json()
  print(data)
else:
  print(f"Error: API request failed with status code {response.status_code}")
  print(response.text)


######################visual crossing #################################################
print("######################visual crossing #################################################")
# Replace {API_KEY} with your actual visual cross API key
VC_api_key = "5ZWKQDPX8WZDZFLAWWL7LMPAE"

# Define country as variable
country = "singapore"


# Define the API endpoint URL with placeholders
url = f"https://weather.visualcrossing.com/VisualCrossingWebServices/rest/services/timeline/{country}?unitGroup=us&key={VC_api_key}&contentType=json"
print(url)

# Send a GET request to the API endpoint
response = requests.get(url)

# Check for successful response (status code 200)
if response.status_code == 200:
  # Convert the JSON response to a Python dictionary
  data = response.json()
  print(data)
else:
  print(f"Error: API request failed with status code {response.status_code}")
  print(response.text)

######################Open weather#################################################
# Replace {API_KEY} with your actual OpenWeatherMap API key
api_key = "827db554784d6d5cd704af90e92577b4"

# Define latitude and longitude as variables
latitude = 35  # Replace with your desired latitude
longitude = 139  # Replace with your desired longitude

# Define the API endpoint URL with placeholders
url = f"https://api.openweathermap.org/data/2.5/weather?lat={latitude}&lon={longitude}&appid={api_key}"
print(url)

# Send a GET request to the API endpoint
response = requests.get(url)

# Check for successful response (status code 200)
if response.status_code == 200:
  # Convert the JSON response to a Python dictionary
  data = response.json()
  print(data)
else:
  print(f"Error: API request failed with status code {response.status_code}")
  print(response.text)
