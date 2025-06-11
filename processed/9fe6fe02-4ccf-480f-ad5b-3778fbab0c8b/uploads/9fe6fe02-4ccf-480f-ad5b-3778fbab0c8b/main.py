# import necessary libraries

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service

# pip install webdriver-manager
from webdriver_manager.chrome import ChromeDriverManager
from os import getcwd

chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument("--use-fake-ui-for-media-stream")
chrome_options.add_argument("--headless-- = new")

driver = webdriver.Chrome(
    service=Service(ChromeDriverManager().install()), options=chrome_options
)

website = f"{getcwd()}\\index.html"

driver.get(website)

rec_file = f"{getcwd()}\\input.txt"


def listen():
    try:
        start_button = WebDriverWait(driver, 20).until(
            EC.element_to_be_clickable((By.ID, "startButton"))
        )
        start_button.click()
        print("Recording started...")
        output_text = ""
        is_second_click = False
        while True:
            output_element = WebDriverWait(driver, 20).until(
                EC.presence_of_element_located((By.ID, "output"))
            )
            current_text = output_element.text.split()
            if "Start Listening" in start_button.text and is_second_click:
                if output_text:
                    is_second_click = False
            elif "listening..." in start_button.text:
                is_second_click = False  # Fixed typo
                if (
                    current_text != output_text
                ):  # Ensure both are strings for comparison
                    output_text = " ".join(current_text)  # Convert list to string
                    with open(rec_file, "w") as file:
                        file.write(output_text)  # Removed incorrect function call
                        print("USER:", output_text)  # Fixed concatenation

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(e)


listen()
