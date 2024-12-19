from PIL import Image
import numpy as np
import os
import json
import pyfiglet  

class AdvancedImageEncryptor:
    def __init__(self, key: str):
        """
        Initialize the AdvancedImageEncryptor with a key.
        :param key: Encryption/Decryption key (string).
        """
        self.key = self._generate_numeric_key(key)

    @staticmethod
    def _generate_numeric_key(key: str):
        """
        Convert the string key into a numeric array.
        :param key: String key.
        :return: Numeric key as a numpy array.
        """
        return np.array([ord(char) for char in key], dtype=np.uint8)

    def _xor_encrypt(self, pixel_array: np.ndarray):
        """
        Perform XOR encryption on the pixel array.
        :param pixel_array: Original pixel array.
        :return: Encrypted pixel array.
        """
        flat_pixels = pixel_array.flatten()
        key_repeated = np.tile(self.key, len(flat_pixels) // len(self.key) + 1)
        return np.bitwise_xor(flat_pixels, key_repeated[:len(flat_pixels)]).reshape(pixel_array.shape)

    def _xor_decrypt(self, encrypted_array: np.ndarray):
        """
        Perform XOR decryption (same as encryption for XOR).
        :param encrypted_array: Encrypted pixel array.
        :return: Decrypted pixel array.
        """
        return self._xor_encrypt(encrypted_array)

    def encrypt(self, input_path: str, output_path: str):
        """
        Encrypt an image and save it.
        :param input_path: Path to the input image.
        :param output_path: Path to save the encrypted image.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file '{input_path}' not found.")

        image = Image.open(input_path)
        pixel_array = np.array(image)

        encrypted_array = self._xor_encrypt(pixel_array)

        encrypted_image = Image.fromarray(np.uint8(encrypted_array))
        encrypted_image.save(output_path)

        metadata = {'key_length': len(self.key)}
        with open(output_path + ".meta", "w") as meta_file:
            json.dump(metadata, meta_file)

        print(pyfiglet.figlet_format("Image Encryption"))
        print(f"Image encrypted and saved to {output_path}.")

    def decrypt(self, input_path: str, output_path: str):
        """
        Decrypt an encrypted image.
        :param input_path: Path to the encrypted image.
        :param output_path: Path to save the decrypted image.
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file '{input_path}' not found.")

        metadata_path = input_path + ".meta"
        if not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata file '{metadata_path}' not found.")
        with open(metadata_path, "r") as meta_file:
            metadata = json.load(meta_file)

        image = Image.open(input_path)
        encrypted_array = np.array(image)

        decrypted_array = self._xor_decrypt(encrypted_array)

        decrypted_image = Image.fromarray(np.uint8(decrypted_array))
        decrypted_image.save(output_path)
        
        print(pyfiglet.figlet_format("Image Decryption"))
        print(f"Image decrypted and saved to {output_path}.")


if __name__ == "__main__":
    key = "my_secure_key_123"  
    encryptor = AdvancedImageEncryptor(key)

    print("Choose an operation:")
    print("1. Encrypt an image")
    print("2. Decrypt an image")
    choice = input("Enter your choice (1/2): ")

    if choice == "1":
        input_path = input("Enter the full path to the image to encrypt: ")
        output_path = input("Enter the output path for the encrypted image: ")
        encryptor.encrypt(input_path, output_path)
    elif choice == "2":
        input_path = input("Enter the full path to the encrypted image: ")
        output_path = input("Enter the output path for the decrypted image: ")
        encryptor.decrypt(input_path, output_path)
    else:
        print("Invalid choice. Please enter 1 or 2.")
