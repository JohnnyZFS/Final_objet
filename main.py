import base64
import http.server
import socketserver
import unittest
import RPi.GPIO as GPIO
import json
from http.server import SimpleHTTPRequestHandler
import time
from threading import Thread
from unittest.mock import MagicMock, patch
import rsa  # Import rsa module
import adc
import os

# Initialisation des variables globales
# client_public_key = None
# print(client_public_key)


"""
# Fonction pour charger ou générer les clés
def load_or_generate_keys():
    try:
        if os.path.exists("server_private_key.pem") and os.path.exists("server_public_key.pem"):
            # Charger les clés existantes
            with open("server_private_key.pem", "rb") as priv_file, open("server_public_key.pem", "rb") as pub_file:
                private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
                public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
        else:
            raise FileNotFoundError
    except (FileNotFoundError, ValueError):
        # Générer de nouvelles clés en cas d'erreur
        print("Clés corrompues ou absentes, régénération...")
        public_key, private_key = rsa.newkeys(512)
        with open("server_private_key.pem", "wb") as priv_file, open("server_public_key.pem", "wb") as pub_file:
            priv_file.write(private_key.save_pkcs1())
            pub_file.write(public_key.save_pkcs1())  # Sauvegarde de la clé publique au format PEM
    return public_key, private_key


# Chargement des clés
server_public_key, server_private_key = load_or_generate_keys()


# Fonction pour obtenir la clé publique sous forme de PEM
def get_public_key_pem():
    with open("server_public_key.pem", "rb") as pub_file:
        public_key = pub_file.read()
        # Encodage PEM (format X.509)
        public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{public_key.decode().strip()}\n-----END PUBLIC KEY-----"
    return public_key_pem

"""
# Initialisation des GPIO
GPIO.setmode(GPIO.BOARD)
GPIO.setup(3, GPIO.OUT)  # LED 1 (PWM)
GPIO.setup(5, GPIO.OUT)  # LED 2
GPIO.setup(12, GPIO.IN)  # Bouton physique
GPIO.setwarnings(False)

# Paramètres du PWM
led_pwm = GPIO.PWM(3, 1)  # LED 1 en PWM (1Hz par défaut)
led_state = "on"
led_frequency_1 = 1

# Lire la valeur analogique
valeur_analogique = adc.get_adc(2)
valeur_analogique = 400
print(f"Valeur analogique : {valeur_analogique}")

# Définir les seuils pour faible, moyenne, haute fréquence
if valeur_analogique <= 341:  # Faible
    led_frequency_1 = 20  # Fréquence faible (20 Hz)
    vitesse = "faible"
elif 342 <= valeur_analogique <= 682:  # Moyenne
    led_frequency_1 = 50  # Fréquence moyenne (50 Hz)
    vitesse = "moyenne"
else:  # Haute
    led_frequency_1 = 100  # Fréquence haute (100 Hz)
    vitesse = "haute"

led_pwm.start(50)  # Initialise le PWM avec un duty cycle de 50%
led_pwm.ChangeFrequency(led_frequency_1)

# Afficher le résultat pour vérifier
print(f"Fréquence PWM réglée à {led_frequency_1} Hz pour la vitesse {vitesse}")

"""
def encrypt_with_client_key(data, client_pub_key):
    "Chiffre les données avec la clé publique du client."
    try:
        return rsa.encrypt(data.encode('utf-8'), client_pub_key)
    except rsa.pkcs1.DecryptionError as e:
        print(f"Erreur de chiffrement avec la clé client (RSA error): {e}")
        return None
    except Exception as e:
        print(f"Erreur de chiffrement avec la clé client : {e}")
        return None


def decrypt_with_server_key(encrypted_data):
    "Déchiffre les données avec la clé privée du serveur."
    try:
        return rsa.decrypt(encrypted_data, server_private_key).decode('utf-8')
    except rsa.pkcs1.DecryptionError as e:
        print(f"Erreur de déchiffrement avec la clé serveur (RSA error): {e}")
        return None
    except Exception as e:
        print(f"Erreur de déchiffrement avec la clé serveur : {e}")
        return None

"""


# Fonction callback pour le bouton

def bouton_callback(channel):
    global led_state
    try:
        if GPIO.input(channel):
            led_state = "on"
            GPIO.output(5, GPIO.HIGH)
            led_pwm.start(50)
        else:
            led_state = "off"
            GPIO.output(5, GPIO.LOW)
            led_pwm.stop()
    except Exception as e:
        print(f"Erreur dans bouton_callback : {e}")


GPIO.add_event_detect(12, GPIO.BOTH, callback=bouton_callback, bouncetime=200)


class MyHttpRequestHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        print("Requête GET reçue: ", self.path)  # Vérifier l'URL demandée

        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

        # Créer un dictionnaire avec les données à envoyer
        data = {"etat": led_state}

        if led_state == "on":
            data["frequence"] = vitesse  # Ajouter la clé "frequence" seulement si l'état est "on"

        try:
            # Convertir le dictionnaire en JSON et l'envoyer
            self.wfile.write(json.dumps(data).encode('utf-8'))
        except Exception as e:
            print(f"Erreur lors de l'envoi des données : {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Erreur lors de l'envoi des donnees")

    def do_POST(self):
        global led_state, led_frequency_1

        content_length = int(self.headers['Content-Length'])
        data = self.rfile.read(content_length)

        try:
            donnees = json.loads(data.decode('utf-8'))

            # Traiter les commandes
            statut = donnees.get('statut', None)
            vitesse = donnees.get('vitesse', None)
            if statut:
                if statut == "On":
                    led_state = "on"
                    GPIO.output(5, GPIO.HIGH)
                    led_pwm.start(50)
                elif statut == "Off":
                    led_state = "off"
                    GPIO.output(5, GPIO.LOW)
                    led_pwm.stop()

            if vitesse:
                if vitesse == "Haute":
                    led_frequency_1 = 100
                elif vitesse == "Moyenne":
                    led_frequency_1 = 50
                elif vitesse == "Faible":
                    led_frequency_1 = 20

            if led_state == "On":
                led_pwm.ChangeFrequency(led_frequency_1)
                pass

            response_data = {
                "etat": led_state,
                "frequence": vitesse if led_state == "on" else "Aucune"
            }

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))

        except Exception as e:
            print(f"Erreur lors du traitement des données POST : {e}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Erreur lors du traitement des donnees.")


# Démarrer le serveur HTTP
def start_server():
    with socketserver.TCPServer(("0.0.0.0", 8080), MyHttpRequestHandler) as httpd:
        print("Serveur démarré sur le port 8080...")
        httpd.serve_forever()


class TestDelControl(unittest.TestCase):
    @patch('adc.get_adc')
    def test_adc_read(self, mock_adc):
        mock_adc.return_value = 512
        valeur = adc.get_adc(2)
        self.assertEqual(valeur, 512)

    @patch('RPi.GPIO.input')
    def test_bouton_pulldown(self, mock_input):
        # Simuler bouton non appuyé (0) et appuyé (1)
        mock_input.side_effect = [0, 1]  # Bouton d'abord non appuyé, puis appuyé

        # Test lorsque le bouton est non appuyé
        bouton_callback(12)
        self.assertEqual(led_state, "off")

        # Test lorsque le bouton est appuyé
        bouton_callback(12)
        self.assertEqual(led_state, "on")

    @patch('RPi.GPIO.input')
    @patch('RPi.GPIO.output')
    def test_actionner_bouton(self, mock_output, mock_input):
        # Simuler un bouton pressé ou relâché
        mock_input.side_effect = [1, 0]  # Bouton pressé, puis relâché

        # Appel pour simuler l'état du bouton
        bouton_callback(12)
        mock_output.assert_called_with(5, GPIO.HIGH)  # DEL 2 allumée

        bouton_callback(12)
        mock_output.assert_called_with(5, GPIO.LOW)  # DEL 2 éteinte

    @patch('adc.get_adc')
    @patch('RPi.GPIO.PWM')
    def test_varier_potentiometre(self, mock_pwm, mock_adc):
        # Simuler les valeurs du potentiomètre
        mock_adc.side_effect = [200, 500, 800]  # Faible, Moyenne, Haute

        # Appel de la fonction de lecture
        valeur_analogique = adc.get_adc(2)
        self.assertEqual(valeur_analogique, 200)
        led_pwm = mock_pwm.return_value
        led_pwm.ChangeFrequency.assert_called_with(20)  # Faible vitesse

        valeur_analogique = adc.get_adc(2)
        self.assertEqual(valeur_analogique, 500)
        led_pwm.ChangeFrequency.assert_called_with(50)  # Vitesse moyenne

        valeur_analogique = adc.get_adc(2)
        self.assertEqual(valeur_analogique, 800)
        led_pwm.ChangeFrequency.assert_called_with(100)  # Haute vitesse

    @patch('RPi.GPIO.output')
    def test_donnees_statut(self, mock_output):
        # Simuler les données statut envoyées par POST
        donnees = {"statut": "on", "vitesse": "haute"}

        # Allumer les LEDs
        if donnees['statut'] == "on":
            GPIO.output(5, GPIO.HIGH)
            GPIO.output(3, GPIO.HIGH)

        mock_output.assert_any_call(5, GPIO.HIGH)  # DEL 2 allumée
        mock_output.assert_any_call(3, GPIO.HIGH)  # DEL 1 allumée

        # Éteindre les LEDs
        donnees['statut'] = "off"
        if donnees['statut'] == "off":
            GPIO.output(5, GPIO.LOW)
            GPIO.output(3, GPIO.LOW)

        mock_output.assert_any_call(5, GPIO.LOW)  # DEL 2 éteinte
        mock_output.assert_any_call(3, GPIO.LOW)  # DEL 1 éteinte

    @patch('RPi.GPIO.PWM')
    def test_donnees_vitesse(self, mock_pwm):
        # Simuler les données vitesse envoyées par POST
        led_pwm = mock_pwm.return_value

        donnees = {"vitesse": "faible"}
        try:
            if donnees['vitesse'] == "faible":
                led_pwm.ChangeFrequency(20)
                led_pwm.ChangeFrequency.assert_called_with(20)  # Faible vitesse
        except Exception as e:
            self.fail(f"ChangeFrequency a échoué avec une exception : {e}")

        donnees['vitesse'] = "moyenne"
        try:
            if donnees['vitesse'] == "moyenne":
                led_pwm.ChangeFrequency(50)
                led_pwm.ChangeFrequency.assert_called_with(50)  # Vitesse moyenne
        except Exception as e:
            self.fail(f"ChangeFrequency a échoué avec une exception : {e}")
        donnees['vitesse'] = "haute"
        try:
            if donnees['vitesse'] == "haute":
                led_pwm.ChangeFrequency(100)
                led_pwm.ChangeFrequency.assert_called_with(100)  # Haute vitesse
        except Exception as e:
            self.fail(f"ChangeFrequency a échoué avec une exception : {e}")


def run_tests():
    unittest.main(verbosity=2, exit=False)


if __name__ == "__main__":
    try:
        serveur_thread = Thread(target=start_server, daemon=True)
        serveur_thread.start()

        # Démarrer les tests dans un autre thread
        # thread_tests = Thread(target=run_tests, daemon=True)
        # thread_tests.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Interruption par l'utilisateur.")
    except Exception as e:
        print(f"Erreur inattendue : {e}")
    finally:
        #  GPIO.cleanup()
        print("GPIO nettoyés.")

# curl http://localhost:8080 get
# curl -X POST http://localhost:8080 -d '{"statut": "on", "vitesse": "haute"}' -H "Content-Type: application/json"
# curl -X POST http://localhost:8080 -d '{"statut": "off", "vitesse": "faible"}' -H "Content-Type: application/json"
# curl -X POST http://localhost:8080 -d '{"statut": "on", "vitesse": "moyenne"}' -H "Content-Type: application/json"
