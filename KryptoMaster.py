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
                    Last Updated : 25/04/2022
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


#--------Registration window-------------
def reg_wind():
    cursor = con.cursor()
    reg_window = tk.Tk()
    reg_window.geometry('500x650')
    reg_window.title("Krypto Master - Registration Form")
    reg_window.resizable(0, 0)
    reg_window.configure(bg="#e7eaf6")


    reg_img = tk.PhotoImage(file = resource_path(r"resources\register_img.png"))
    reg_img_lab = tk.Label(reg_window, image = reg_img)
    reg_img_lab.pack(pady=20)
    reg_window.iconbitmap(resource_path(r'resources\icon.ico'))
    
    global lab_status

    create_var_reg()
     
    def helpp():
        tk.messagebox.showinfo(
                "How to Register:", '''Enter all your details correctly 
                and click on register.
                
                Constraints:
                1. Username should be Alpha Numeric.
                2. Phone number should be 10 digits.
                3. Password should consist of at least of 8 characters.
                4. Email - ID should be valid.''')


    def ext():
        reg_window.destroy()
    
    
    def clear(): #reseting all the fields for fresh entry of data
        username.set('')
        phone.set('')
        password.set('')
        conf_password.set('')
        email.set('')
        lab_status.config(text='---')


    def register():
        if verify('reg'):
            if sql_reg(username.get(), password.get(), phone.get(), email.get()):
                reg_window.destroy()
                login_wind()

        
    #-------------Menu---------------
    menu = tk.Menu(reg_window)
    reg_window.config(menu=menu)
    
    
    file_menu = tk.Menu(menu)
    file_menu.add_command(label="Exit", command=ext)
    menu.add_cascade(label="File", menu=file_menu)
    
    
    option = tk.Menu(menu)
    option.add_command(label="About", command=about)
    option.add_command(label="Help", command=helpp)
    menu.add_cascade(label="Option", menu=option)
        
        
    #--------------------------Labels and Entries-----------------
    label_0 = tk.Label(reg_window,
                       text="Registration Form",
                       relief="solid",
                       width=20,
                       font=("arial", 24, "bold"),
                       bg="#e7eaf6")
    label_0.place(x=50,y=150)
    
    
    lab_user = tk.Label(reg_window,
                        text = "Username :",
                        width = 20,
                        font = ("bold", 14),
                        bg="#e7eaf6")
    lab_user.place(x=80,y=240)
    
    
    entry_user = tk.Entry(reg_window,
                          textvar=username,
                          font=('arial',12),
                          relief=tk.FLAT)
    entry_user.place(x=270,y=242)
    
    
    lab_phone = tk.Label(reg_window,
                         text='Phone No :',
                         width=20,
                         font=("bold", 14),
                         bg="#e7eaf6")
    lab_phone.place(x=80,y=280)
    
    
    entry_phone = tk.Entry(reg_window,
                           textvar=phone,
                           font=('arial', 12),
                           relief=tk.FLAT)
    entry_phone.place(x=270, y=282)
    
    
    lab_pass = tk.Label(reg_window,
                        text='Password :',
                        width=20,
                        font=("bold", 14),
                        bg="#e7eaf6")
    lab_pass.place(x=80, y=320)
    
    
    entry_pass = tk.Entry(reg_window,
                          textvar=password,
                          show='*',
                          font=('arial', 12),
                          relief=tk.FLAT)
    entry_pass.place(x=270, y=320)
    
    
    lab_confpass = tk.Label(reg_window,
                            text='Confirm Password :',
                            width=20,
                            font=("bold", 14),
                            bg="#e7eaf6")
    lab_confpass.place(x=45, y=360)
    
    
    entry_confpass = tk.Entry(reg_window,
                              textvar=conf_password,
                              show='*',
                              font=('arial', 12),
                              relief=tk.FLAT)
    entry_confpass.place(x=270, y=360)
    
    
    lab_email = tk.Label(reg_window,
                         text='E-Mail ID :',
                         width=20,
                         font=("bold", 14),
                         bg="#e7eaf6")
    lab_email.place(x=85, y=400)
    
    
    entry_email = tk.Entry(reg_window,
                           textvar=email,
                           font=('arial', 12),
                           relief=tk.FLAT)
    entry_email.place(x=272, y=400)


    lab_status = tk.Label(reg_window,
                          text='---',
                          fg ='red',
                          bg="#e7eaf6",
                          font=("bold", 10))
    lab_status.place(x=20, y=600)


    #--------------Buttons--------------
    but_reg=tk.Button(reg_window,
                      text='Register',
                      width=12,
                      font=('bold'),
                      bg="#1089ff",
                      relief=tk.FLAT,
                      fg='white',
                      command = register).place(x=30, y=515)
    
    
    but_clear=tk.Button(reg_window,
                        text='Clear',
                        width=12,
                        font=('bold'),
                        bg="#1089ff",
                        relief=tk.FLAT,
                        fg='white',
                        command=clear).place(x=180, y=515)
    
    
    but_quit=tk.Button(reg_window,
                       text='Quit',
                       width=12,
                       font=('bold'),
                       bg="#1089ff",
                       relief=tk.FLAT,
                       fg='white',
                       command=ext).place(x=330, y=515)
        
    reg_window.mainloop()
    cursor.close()


#---------------Login window---------------------
def login_wind():
    cursor = con.cursor()
    login_window=tk.Tk()
    login_window.title("Krypto Master 1.0")
    login_window.geometry("500x570")
    login_window.resizable(0, 0)
    login_window.configure(bg="#e7eaf6")

    log_img = tk.PhotoImage(file = resource_path(r"resources\login_img.png"))
    log_img_lab = tk.Label(login_window, image=log_img)
    log_img_lab.pack(pady=10)
    login_window.iconbitmap(resource_path(r'resources\icon.ico'))
    
    global lab_status

    create_var_login()
    
    def helpp():
        tk.messagebox.showinfo(
                "How to Login",'''Enter your credentials correctly and click on Login
                Click on Register if you are a new user.''')


    def clear():
        username.set('')
        password.set('')
        lab_status.config(text='---')
        
        
    def ext():
        login_window.destroy()
        
        
    def open_reg_wind():
        login_window.destroy()
        reg_wind()
        
        
    def open_dash_wind(u,p):
        login_window.destroy()
        dash_wind(u,p)    


    def login():
        if verify(None,'log'):
            sql_login(username.get(), password.get())
            if bool == 1:
                open_dash_wind(username.get(), password.get())
            elif bool == 2:
                lab_status.config(text='Please enter the correct password!!!')
            else:
                lab_status.config(text='You are not registered. Please register yourself!!!')
                
                

    #---------------------------Menu---------------------------
    menu = tk.Menu(login_window)
    login_window.config(menu=menu)
    
    
    file_menu = tk.Menu(menu)
    file_menu.add_command(label="Exit", command=ext)
    menu.add_cascade(label="File", menu=file_menu)
    
    
    option = tk.Menu(menu)
    option.add_command(label="About", command=about)
    option.add_command(label="Help", command=helpp)
    menu.add_cascade(label="Option", menu=option)


# --------------------------Labels and Entries-----------------------------
    label_0 = tk.Label(login_window,
                       text="Login in to Krypto Master",
                       relief="solid",
                       width=22,
                       font=("arial", 24,"bold"),
                       bg="#e7eaf6")
    label_0.place(x=30, y=150)


    lab_user = tk.Label(login_window,
                        text="Username :",
                        width=20,
                        font=("bold", 14),
                        bg="#e7eaf6")
    lab_user.place(x=70, y=310)
    
    
    entry_user = tk.Entry(login_window,
                          textvar=username,
                          font=('arial',12),
                          relief=tk.FLAT)
    entry_user.place(x=260, y=315)


    lab_password = tk.Label(login_window,
                            text='Password :',
                            width=20,
                            font=("bold", 14),
                            bg="#e7eaf6")
    lab_password.place(x=70, y=350)
    
    
    entry_pass = tk.Entry(login_window,
                          textvar=password,
                          show = '*',
                          font=('arial',12),
                          relief=tk.FLAT)
    entry_pass.place(x=260,y=355)


    lab_status = tk.Label(login_window, 
                          text='---',
                          fg ='red',
                          bg="#e7eaf6",
                          font=("bold", 10))
    lab_status.place(x=20, y=520)
    
    
    #--------------Buttons--------------
    but_login = tk.Button(login_window,
                        text='Login',
                        width=12,
                        font=('bold'),
                        bg="#1089ff",
                        relief=tk.FLAT,
                        fg='white',
                        command=login).place(x=25, y=415)
    
    
    but_clear=tk.Button(login_window,
                        text='Clear',
                        width=12,
                        font=('bold'),
                        bg="#1089ff",
                        relief=tk.FLAT,
                        fg='white',
                        command=clear).place(x=177, y=415)
    
    
    but_register = tk.Button(login_window,
                           text='Register',
                           width=12,
                           font=('bold'),
                           bg="#1089ff",
                           relief=tk.FLAT,
                           fg='white',
                           command=open_reg_wind).place(x=330, y=415)
    
    
    but_quit = tk.Button(login_window,
                       text='Quit',
                       width=12,
                       font=('bold'),
                       bg="#1089ff",
                       relief=tk.FLAT,
                       fg='white',
                       command=ext).place(x=175, y=475)
    
    login_window.mainloop()
    cursor.close()
  
 
#--------------Dashboard Window--------------
def dash_wind(u,p):
    cursor = con.cursor()
    dash_window = tk.Tk()
    dash_window.geometry('600x600')
    dash_window.title(u.capitalize() + " - Your Dashboard")
    dash_window.resizable(0,0)
    dash_window.configure(bg="#e7eaf6")
    
    dash_window.iconbitmap(resource_path(r'resources\icon.ico'))
    
    global lab_status
    
    create_var_dash()
    
    def helpp():
        tk.messagebox.showinfo(
            "Usage Guide",
            """
            1. Click SELECT FILE Button and select your file (e.g. abc.txt)
            2.Enter your Secret Key (This can be any alphanumeric letters). 
            Remember this so you can Decrypt the file later.
            3. Click ENCRYPT Button to encrypt. A new encrypted file with 
            ".enc" extention (e.g. abc.txt.enc) will be created in another 
            directory.
            4. When you want to Decrypt a file select the file in the menu. 
            Click DECRYPT Button to decrypt. The decrypted file will be of
            the same name as before "abc.txt".
            5. Click CLEAR Button to clear the input fields.""")


    def clear():
        global source_file
        path.set('')
        key.set('')
        combo_encfiles.current(0)
        lab_status.config(text='---')
        but_encrypt['state'] = 'normal'
        but_decrypt['state'] = 'normal'
        
        
    def combobox_data():
        global combo_disp
        cursor.execute("Select o_filename from " + u)
        combo_disp = cursor.fetchall()
        
        
    def combobox_selection(event):
        but_encrypt['state'] = 'disabled'
        but_decrypt['state'] = 'normal'
        cursor.execute("Select o_filepath from " + str(u) + " where uid= \'" + str(combo_encfiles.current()) + '\'')
        path.set(cursor.fetchall()[0][0])
        entry_path.config(state='readonly')
           
        
    def combobox_update():
        combo_encfiles['values'] = combo_val
        
        
    def update_uid():
        cursor.execute('Select uid from ' + u)
        uids=cursor.fetchall()
        for i in range(len(uids)):
            upd_uid = "update {} set uid= {} where uid= '{}'".format(u,str(i+1),uids[i][0])
            cursor.execute(upd_uid)
            con.commit()
        
        
    def browse_func():
        global source_file,file_split
        but_decrypt['state'] = 'disabled'
        but_encrypt['state'] = 'normal'
        source_file = filedialog.askopenfilename().replace('/','\\\\')
        path.set(source_file)
        entry_path.config(state='readonly')
        file_split = os.path.split(source_file)
        
        
    def open_login_wind():
        dash_window.destroy()
        login_wind()
        
        
    def dash_verify():
        lab_status.config(text='---')
        if path.get() == '' or path.get().isspace(): #label.cget('text'),lable['text']
            lab_status.config(text='Please select a file to operate/work on!!!')
            return False
        elif len(key.get()) < 4:
            lab_status.config(text='Please enter a key with minimum of 4 characters!!!')
            return False
        return True
        
    
    def encrypt_btn():
        try:
            if dash_verify():
                lab_status.config(text='Encrypting.....')
    
                with open(source_file,'r') as f:
                    raw = f.read()
                
                encryp_data = encrypt(raw,key.get())
                encryp_fname = fname_modify(file_split[1][:-4]) + '.txt.enc'        
                      
                with open(encrypt_dir + encryp_fname ,'wb') as f:
                    f.write(encryp_data)            
                os.remove(source_file)
                tk.messagebox.showinfo(
                    "Original File Status",
                    '''Your original file was deleted successfully.''')
        
                cursor.execute('Select uid from ' + u)
                uid = len(cursor.fetchall()) + 1
                ins = "insert into " + u +" (uid,o_filepath,o_filename,enc_filename,sec_key) " \
                "values ('{}','{}','{}','{}','{}')".format(uid,source_file,file_split[1],encryp_fname,key.get())
                cursor.execute(ins)
                con.commit()
                combo_val.append(file_split[1])
                clear()
                lab_status.config(text='Encrypted Successfully')
                
        except FileNotFoundError:
            lab_status.config(text='The Original File or Directory has got deleted, so cannot Encrypt.')
        except UnicodeDecodeError:
            lab_status.config(text='Sorry, currently this file format is not supported')
        except:
            lab_status.config(text='')
            tk.messagebox.showinfo(
                    "Sorry",
                    '''Sorry, Currently we are unavailable.
                    Try again later or contact the Developers.''')


    def decrypt_btn():
        try:
            if dash_verify():
                lab_status.config(text='Decrypting.....')
                cursor.execute("Select sec_key,o_filepath,enc_filename,o_filename from " 
                               + str(u) + " where uid= \'" + str(combo_encfiles.current()) + '\'' )
                decryp_cred = cursor.fetchall()
                
                if key.get() == decryp_cred[0][0]:
                    with open(encrypt_dir + decryp_cred[0][2],'rb') as f:
                        raw=f.read()
                            
                    decryp_data = decrypt(raw,key.get())
                        
                    with open(decryp_cred[0][1],'w') as f:
                        f.write(decryp_data)
                                
                    os.remove(encrypt_dir + decryp_cred[0][2])
                    tk.messagebox.showinfo(
                            "Ecrypted File Status",
                            '''Your encrypted file was deleted successfully.''')
                    cursor.execute("delete from " + u + " where uid= \'" + str(combo_encfiles.current()) + '\'')
                    con.commit()
                    update_uid()
                    combo_val.remove(decryp_cred[0][3])
                    clear()
                    lab_status.config(text='Decrypted Successfully') 
                else:
                    lab_status.config(text='Enter the correct Secret Key.')
        
        except FileNotFoundError:
            lab_status.config(text='The Encrypted file or Directory has got deleted, so cannot Decrypt.')
        except:
            lab_status.config(text='')
            tk.messagebox.showinfo(
                    "Sorry",
 '''Sorry, Currently we are unavailable.
 Try again later or contact the Developers.''')
             
            
# ---------------------Frames--------------------------
    Top = tk.Frame(dash_window, padx=10, pady=10, bg="#e7eaf6")
    Top.pack(padx=10, pady=10, fill=tk.X)
    
     
# ------------------Combobox-------------------
    combo_val=['Please select a file to be Decrypted']
    combobox_data()
    for i in combo_disp:
        combo_val.append(i[0])
    combo_encfiles = ttk.Combobox(dash_window, 
                                  width=35,
                                  values=combo_val,
                                  textvar=combo,
                                  postcommand=combobox_update,
                                  font=('arial',12))
    combo_encfiles.current(0)
    combo_encfiles.bind("<<ComboboxSelected>>", combobox_selection)
    combo_encfiles.place(x=115,y=350)


# -------------Menu---------------
    menu = tk.Menu(dash_window)
    dash_window.config(menu=menu)
        
    
    option = tk.Menu(menu)
    option.add_command(label='Logout', command=open_login_wind)
    option.add_command(label='About', command=about)
    menu.add_cascade(label='Option', menu=option)
    menu.add_command(label='Help', command=helpp)


# ----------------------------------------Labels and Entries-----------------------------------
    lab_welcome = tk.Label(Top,
                           text="Welcome " + u.capitalize(),
                           relief="solid",
                           width=20,
                           font=("arial", 24,"bold"),
                           bg="#e7eaf6")
    lab_welcome.pack(fill=tk.X)
    
    
    lab_path = tk.Label(dash_window, 
                        text="File Path :",
                        width=10,
                        font=("bold", 14),
                        bg="#e7eaf6")
    lab_path.place(x=50, y=100)
    
    
    entry_path = tk.Entry(dash_window,
                          textvar = path,
                          width = 40,
                          font=('arial',12),
                          relief=tk.FLAT)
    entry_path.place(x=195, y=105)
    
    
    lab_key = tk.Label(dash_window,
                       text='Secret Key :',
                       width=10,
                       font=("bold", 14),
                       bg="#e7eaf6")
    lab_key.place(x=40, y=130)
    
    
    entry_key = tk.Entry(dash_window,
                         textvar=key,
                         show='*',
                         font=('arial',12),
                         relief=tk.FLAT)
    entry_key.place(x=195, y=135)
    
    
    lab_status = tk.Label(dash_window,
                          text='---',
                          fg ='red',
                          bg="#e7eaf6",
                          font=("bold", 10))
    lab_status.place(x=25, y=550)
     
    
    #--------------Buttons--------------
    but_select_file = tk.Button(dash_window,
                                text='Select File..',
                                font=('bold'),
                                bg="#1089ff",
                                relief=tk.FLAT,
                                fg='white',
                                width=45,
                                command=browse_func).place(x=50, y = 180)
    
    
    but_encrypt = tk.Button(dash_window,
                            text='Encrypt',
                            width=12,
                            font=('bold'),
                            bg="#1089ff",
                            relief=tk.FLAT,
                            fg='white',
                            command=encrypt_btn)
    but_encrypt.place(x=215, y=250)
    
    
    but_decrypt = tk.Button(dash_window,
                            text='Decrypt',
                            width=12,
                            font=('bold'),
                            bg="#1089ff",
                            relief=tk.FLAT,
                            fg='white',
                            command=decrypt_btn)
    but_decrypt.place(x=215, y=410)
    
    
    but_clear=tk.Button(dash_window,
                        text='Clear',
                        width=12,
                        font=('bold'),
                        bg="#1089ff",
                        relief=tk.FLAT,
                        fg='white',
                        command=clear).place(x=215, y=480)
    
    dash_window.mainloop()
    cursor.close()


#----------------Function Calls-----------------------
create_database()


 