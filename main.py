# -*- coding:utf-8 -*-

import telebot
from telebot.types import InlineKeyboardButton, InlineKeyboardMarkup
import os
import sys
import zlib
import time
import base64
import marshal
import py_compile

sahal31 = "8414179160:AAE1oi47K2HjErcx4qEo9gxJJY7XKySY75c"
bot = telebot.TeleBot(sahal31)

zlb = lambda in_ : zlib.compress(in_)
b16 = lambda in_ : base64.b16encode(in_)
b32 = lambda in_ : base64.b32encode(in_)
b64 = lambda in_ : base64.b64encode(in_)
mar  = lambda in_ : marshal.dumps(compile(in_,'<x>','exec'))
note = "# Güzeliğin kadar ömrüm olsa bir ömür yaşarım \n"
def encode_option(option, data):
    loop = 1 
    if option == 1:
        xx = "mar(data.encode('utf8'))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__[::-1]);"
    elif option == 2:
        xx = "zlb(data.encode('utf8'))[::-1]"
        heading = "_ = lambda __ : __import__('zlib').decompress(__[::-1]);"
    elif option == 3:
        xx = "b16(data.encode('utf8'))[::-1]"
        heading = "_ = lambda __ : __import__('base64').b16decode(__[::-1]);"
    elif option == 4:
        xx = "b32(data.encode('utf8'))[::-1]"
        heading = "_ = lambda __ : __import__('base64').b32decode(__[::-1]);"
    elif option == 5:
        xx = "b64(data.encode('utf8'))[::-1]"
        heading = "_ = lambda __ : __import__('base64').b64decode(__[::-1]);"
    elif option == 6:
        xx = "b16(zlb(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b16decode(__[::-1]));"
    elif option == 7:
        xx = "b32(zlb(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b32decode(__[::-1]));"
    elif option == 8:
        xx = "b64(zlb(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));"
    elif option == 9:
        xx = "zlb(mar(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__[::-1]));"
    elif option == 10:
        xx = "b16(mar(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('base64').b16decode(__[::-1]));"
    elif option == 11:
        xx = "b32(mar(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('base64').b32decode(__[::-1]));"
    elif option == 12:
        xx = "b64(mar(data.encode('utf8')))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('base64').b64decode(__[::-1]));"
    elif option == 13:
        xx = "b16(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b16decode(__[::-1])));"
    elif option == 14:
        xx = "b32(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b32decode(__[::-1])));"
    elif option == 15:
        xx = "b64(zlb(mar(data.encode('utf8'))))[::-1]"
        heading = "_ = lambda __ : __import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode(__[::-1])));"
    elif option == 16:  
        for x in range(5):
            method = repr(b64(zlb(mar(data.encode('utf8'))))[::-1])
            data = "exec(__import__('marshal').loads(__import__('zlib').decompress(__import__('base64').b64decode(%s[::-1]))))" % method
        z = []
        for i in data:
            z.append(ord(i))
        sata = "_ = %s\nexec(''.join(chr(__) for __ in _))" % z
        return note + sata
    else:
        return None
    for _ in range(loop):
        data = "exec((_)(%s))" % repr(eval(xx))

    return note + heading + data
sahal_files = {}
@bot.message_handler(commands=['start'])
def start_msg(msg):
    bot.send_message(
        msg.chat.id,
        "🛠 Python Encoder Bot\n\n📌 .py dosyası gönder seçenekleri gör"
    )

@bot.message_handler(content_types=['document'])
def file_upload(msg):
    if not msg.document.file_name.endswith(".py"):
        bot.reply_to(msg, "⚠️ Sadece .py dosyası gönder.")
        return
    
    file_info = bot.get_file(msg.document.file_id)
    file_data = bot.download_file(file_info.file_path)

    filename = msg.document.file_name
    with open(filename, "wb") as f:
        f.write(file_data)

    sahal_files[msg.chat.id] = filename
    buttons = [
        ("Encode Marshal", "1"),
        ("Encode Zlib", "2"),
        ("Encode Base16", "3"),
        ("Encode Base32", "4"),
        ("Encode Base64", "5"),
        ("Encode Zlib,Base16", "6"),
        ("Encode Zlib,Base32", "7"),
        ("Encode Zlib,Base64", "8"),
        ("Encode Marshal,Zlib", "9"),
        ("Encode Marshal,Base16", "10"),
        ("Encode Marshal,Base32", "11"),
        ("Encode Marshal,Base64", "12"),
        ("Encode Marshal,Zlib,B16", "13"),
        ("Encode Marshal,Zlib,B32", "14"),
        ("Encode Marshal,Zlib,B64", "15"),
        ("Simple Encode", "16")
    ]

    menu = InlineKeyboardMarkup(row_width=2)
    menu.add(*[InlineKeyboardButton(text=i[0], callback_data=i[1]) for i in buttons])
    bot.send_message(msg.chat.id, "Encode yöntemini seç:", reply_markup=menu)
@bot.callback_query_handler(func=lambda call: True)
def inline_handler(call):
    option = int(call.data)
    chat_id = call.message.chat.id
    if chat_id not in sahal_files:
        bot.answer_callback_query(call.id, "Dosya yok ❌")
        return
    infile = sahal_files[chat_id]
    code = open(infile).read()
    encoded = encode_option(option, code)
    out = infile.replace(".py", "_ENC.py")
    with open(out, "w") as f:
        f.write(encoded)
    bot.send_document(chat_id, open(out, "rb"), caption="✅ Encode başarılı!")
    os.remove(infile)
    os.remove(out)
    del sahal_files[chat_id]
print("bot pasif")
bot.infinity_polling()
