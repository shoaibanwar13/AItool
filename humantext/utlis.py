import requests
import json
 
def make_paypal_payment(amount, currency, return_url, cancel_url):
    # Set up PayPal API credentials
    client_id =  'ARb7F_y_RiMTeGBuzDFoHJCyv8GhOPmaCs-whsaFl2tQG1HjX7_uCiXLTSy0OkuMUjczFXOv4MD-2lk4'
    secret =  'EGWQ_i1bVkdojBr8ylr42eb2EVDXVTrZTec6ofeJSz5l5yt_uIg5J4Gdl3uZiKnraK9Mj30lkd9EBflT'
    url ="https://api.sandbox.paypal.com"
    # Set up API endpoints
    base_url = url
    token_url = base_url + '/v1/oauth2/token'
    payment_url = base_url + '/v1/payments/payment'

    # Request an access token
    token_payload = {'grant_type': 'client_credentials'}
    token_headers = {'Accept': 'application/json', 'Accept-Language': 'en_US'}
    token_response = requests.post(token_url, auth=(client_id, secret), data=token_payload, headers=token_headers)

    if token_response.status_code != 200:
        return False,"Failed to authenticate with PayPal API",None

    access_token = token_response.json()['access_token']

    # Create payment payload
    payment_payload = {
        'intent': 'sale',
        'payer': {'payment_method': 'paypal'},
        'transactions': [{
            'amount': {'total': str(amount), 'currency': currency},
            'description': 'Vulnvision scan & protect '
        }],
        'redirect_urls': {
            'return_url': return_url,
            'cancel_url': cancel_url
        }
    }

    # Create payment request
    payment_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    payment_response = requests.post(payment_url, data=json.dumps(payment_payload), headers=payment_headers)
    print(payment_response.text)
    if payment_response.status_code != 201:
        return False , 'Failed to create PayPal payment.',None

    payment_id = payment_response.json()['id']
    approval_url = next(link['href'] for link in payment_response.json()['links'] if link['rel'] == 'approval_url')

    return True,payment_id, approval_url
def verify_paypal_payment(payment_id):
    client_id =  'ARb7F_y_RiMTeGBuzDFoHJCyv8GhOPmaCs-whsaFl2tQG1HjX7_uCiXLTSy0OkuMUjczFXOv4MD-2lk4'
    secret =  'EGWQ_i1bVkdojBr8ylr42eb2EVDXVTrZTec6ofeJSz5l5yt_uIg5J4Gdl3uZiKnraK9Mj30lkd9EBflT'
    url ="https://api.sandbox.paypal.com"
    base_url = url
    token_url = base_url + '/v1/oauth2/token'
    payment_url = base_url + '/v1/payments/payment'

    token_payload = {'grant_type': 'client_credentials'}
    token_headers = {'Accept': 'application/json', 'Accept-Language': 'en_US'}
    token_response = requests.post(token_url, auth=(client_id, secret), data=token_payload, headers=token_headers)

    if token_response.status_code != 200:
        print(f"Token response status: {token_response.status_code}")
        print(f"Token response content: {token_response.text}")
        raise Exception('Failed to authenticate with PayPal API.')

    access_token = token_response.json()['access_token']

    payment_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {access_token}'
    }

    payment_details_url = f'{payment_url}/{payment_id}'
    payment_details_response = requests.get(payment_details_url, headers=payment_headers)

    if payment_details_response.status_code != 200:
        print(f"Payment details response status: {payment_details_response.status_code}")
        print(f"Payment details response content: {payment_details_response.text}")
        raise Exception('Failed to retrieve PayPal payment details.')

    payment_status = payment_details_response.json()['state']
    if payment_status == 'approved':
        payer_email = payment_details_response.json()['payer']['payer_info']['email']
        # ... process the order ...
        return True
    else:
        return False
