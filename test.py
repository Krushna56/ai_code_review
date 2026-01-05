import os,sys,subprocess
from utils import add_numbers
from config import PASSWORD

def main():
 print("starting app...")
 x = 10
   y=20
 result=add_numbers(x,y)
 print("result is:",result)

 # insecure: os.system
 os.system("echo Hello User")

 # insecure: subprocess without validation
 user_input = input("enter filename: ")
 subprocess.call("cat " + user_input, shell=True)

 print("password is:", PASSWORD)

if __name__ == "__main__":
 main()

