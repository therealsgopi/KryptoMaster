'''
Krypto Mater 1.0
CS Investigatory Project 2019-20 by 
    S Gopi
    Advaith Prasad Curpod
    Vishnu Bharadwaj B Gargeshwari

This is GUI based based application used to encryt and decrypt
entire text files. Currently very few file types are supported, 
we will add support for more file types in the future.
'''

import sys
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox
from tkinter import filedialog
import mysql.connector as sql
import os
from os import path
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

# ----------Defining path for resources when generating ONE exe file---------
def resource_path(relative_path):
    # Get absolute path to resource, works for dev and for PyInstaller
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)
# -----------------OR------------------
'''
def resource_path(relative_path):
    # Get absolute path to resource, works for dev and for PyInstaller
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)
'''


# ------------Establishing encyption directory--------------

def create_encrypt_dir():
    global encrypt_dir
    try:
        if not path.exists('C:\\Krypto Master Files'):
            os.mkdir('C:\\Krypto Master Files')
            encrypt_dir = "C:\\Krypto Master Files\\"
        else:
            encrypt_dir = "C:\\Krypto Master Files\\"
    except:
        encrypt_dir = ''


# ----------------Establishing SQL Connection-------------------

def create_database():
    try:
        global con, cursor
        con = sql.connect(host="localhost", user="root", passwd="1234")
    except:
        sql_error_window = tk.Tk()
        tk.messagebox.showinfo(
                'MySQL Error',
        '''MySQL not installed or Root password incorrect.
             Contact developers for Support.''')
        sql_error_window.destroy()
        return None   
    
    cursor = con.cursor()     
        
    try:
        cursor.execute('use krypto_master_data')
        
    except:
        cursor.execute("Create database Krypto_Master_Data")

        #Creating the users' table
        cursor.execute('use krypto_master_data')
        crtab = "create table users(username varchar(50) primary key,password varchar(50),phone varchar(10),email varchar(50))"
        cursor.execute(crtab)
        con.commit()
    
    if con.is_connected():
        create_encrypt_dir()
        login_wind()

# ----------------SQL Login------------------------

def sql_login(user, passwd):
    global bool
    cursor.execute("use krypto_master_data")
    cursor.execute("Select username,password from users where username = \'" + user + '\'')
    rec = cursor.fetchall()
    if rec == []:
        bool = 3
    elif user == rec[0][0] and passwd == rec[0][1]:
        bool = 1
    elif user == rec[0][0] and passwd != rec[0][1]:
        bool = 2
    
    
# ----------------SQL Register------------------------

def sql_reg(user, passwd, phone, email):
    ins = "insert into users(username,password,phone,email) values('{}','{}','{}','{}')"
    tab = "create table " + str(user) + " (uid varchar(3) primary key,o_filepath varchar(500),o_filename varchar(100),enc_filename varchar(500),sec_key varchar(40))"
    try:
        cursor.execute(ins.format(user, passwd, phone, email))
        cursor.execute(tab)
        con.commit()  
        tkinter.messagebox.showinfo(
                "Success",
                '''You have been registered successfully.''')
        return True
    except:
        
        tk.messagebox.showinfo(
                'Username Error','''
                Sorry. The username '{}' is already registered.
                Please enter a different username.'''.format(username.get()))
        return False


# ---------------Encryption and Decryption Code-------------------
BLOCK_SIZE = 16

def pad(data):
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(data) % BLOCK_SIZE)


def unpad(data):
    return data[:-ord(data[len(data) - 1:])]
 

def get_private_key(file_key):
    salt = file_key[::-1].encode()
    kdf = PBKDF2(file_key, salt, 64, 1000)
    file_key = kdf[:32]
    return file_key
 
 
def encrypt(raw, file_key):
    file_key = get_private_key(file_key)
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(file_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
 
 
def decrypt(enc, file_key):
    file_key = get_private_key(file_key)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(file_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:])).decode()


def fname_modify(fname):
    encryp_fname = ''
    fname = fname.lower()
    for i in fname:
        encryp_fname+=chr(ord(i) + 200)
    return encryp_fname
        

# -----------------Verifying Data--------------------------------------
def email_verify(mail):
    domfile = open(encrypt_dir + 'domains.txt', 'a+')
    domfile.seek(0)
    domlist = domfile.readlines()

    if len(mail.split('@')) == 2:
        ind = mail.find('@')
    else:
        ind = -1
    
    if ind != -1:
        if (mail[ind+1:]+'\n') in domlist:
            flag = 1
        else:
            import requests
            #-------Checking internet connection-------
            try:
                domtry = requests.get('https://www.google.com')
            except:
                lab_status.config(text='Please connect to internet and try again to verify your E-Mail ID')
                return False
            
            try:
                domtry = requests.get('http://www.'+mail[ind+1:])
                if domtry.status_code < 400:
                    flag = 1
                    if (mail[ind+1:]+'\n') not in domlist: 
                        domfile.write(mail[ind+1:]+'\n')
                else:    
                    lab_status.config(text='Please enter a valid domain, Status of domain:'+str(domtry.status_code))
                    return False
            except:
                lab_status.config(text='Please enter a valid domain.')
                return False
           
        if mail[:ind].isalnum():
            flag+=1
        else:
            lab_status.config(text='Please enter a valid email-id')
    
        if flag == 2:
            return True
    else:
        lab_status.config(text='There is no \'@\' in your mail id')
    domfile.close()

        
def verify(reg=None, log=None):
    lab_status.config(text = '---')
    if reg is not None:
        if not username.get().isalnum():
            lab_status.config(text='Please enter a username without using special characters!!!')
            return False
        elif len(phone.get()) != 10 or not phone.get().isdigit():
            lab_status.config(text='Please enter a valid phone number!!!')
            return False
        elif len(password.get()) < 8:
            lab_status.config(text='Please enter a password with a minimum of 8 characters!!!')
            return False
        elif  conf_password.get() != password.get():
            lab_status.config(text='Password and confirmation password do not match!!!')
            return False
        elif not email_verify(email.get()):
            return False
        return True
    elif log is not None:
        if not username.get().isalnum():
            lab_status.config(text='Please enter a username without using special characters!!!')
            return False
        elif len(password.get()) < 8:
            lab_status.config(text='Please enter a password with a minimum of 8 characters!!!')
            return None
        return True
        

def about():
    tk.messagebox.showinfo(
                'About','''
                    Krypto Master
                    Version : 1.0
                    Last Update : 19/01/2020
                    Developers :-
                       S Gopi
                       Advaith Prasad Curpod
                       Vishnu Bharadwaj B Gargeshwari
                    Special Thanks : Leelambika Ma'am
                    
                    Support us by Donating''')


# ------- Creating Variables------------
def create_var_reg():
    global username, phone, password, conf_password, email
    username = tk.StringVar()
    phone = tk.StringVar()
    password = tk.StringVar()
    conf_password = tk.StringVar()
    email = tk.StringVar()
        
    
def create_var_login():
    global username, password
    username = tk.StringVar()
    password = tk.StringVar()
  
    
def create_var_dash():
    global path,key, combo, source_file
    path = tk.StringVar()
    key = tk.StringVar()
    combo = tk.StringVar()
    source_file = ''