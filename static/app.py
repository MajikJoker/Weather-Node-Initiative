import requests

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
