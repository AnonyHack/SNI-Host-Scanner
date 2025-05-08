from datetime import datetime
import os
import time
import socket
import logging
import requests
from dotenv import load_dotenv
from pymongo import MongoClient
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    CallbackContext,
)
from telegram.error import BadRequest
from aiohttp import web

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.FileHandler('sni_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Bot configuration from environment variables
CONFIG = {
    'token': os.getenv('TELEGRAM_BOT_TOKEN', ''),
    'admin_ids': [int(admin_id) for admin_id in os.getenv('ADMIN_IDS', '').split(',') if admin_id],
    'required_channels': os.getenv('REQUIRED_CHANNELS', 'megahubbots,Freenethubz,Freenethubchannel').split(','),
    'channel_links': os.getenv('CHANNEL_LINKS', 'https://t.me/megahubbots,https://t.me/Freenethubz,https://t.me/Freenethubchannel').split(',')
}

# MongoDB connection
try:
    mongodb_uri = os.getenv('MONGODB_URI')
    if not mongodb_uri:
        raise ValueError("MONGODB_URI environment variable not set")
    
    # Add retryWrites and SSL parameters if not already in URI
    if "retryWrites" not in mongodb_uri:
        if "?" in mongodb_uri:
            mongodb_uri += "&retryWrites=true&w=majority"
        else:
            mongodb_uri += "?retryWrites=true&w=majority"
    
    # Force SSL/TLS connection
    if "ssl=true" not in mongodb_uri.lower():
        if "?" in mongodb_uri:
            mongodb_uri += "&ssl=true"
        else:
            mongodb_uri += "?ssl=true"
    
    client = MongoClient(
        mongodb_uri,
        tls=True,
        tlsAllowInvalidCertificates=False,
        connectTimeoutMS=30000,
        socketTimeoutMS=30000,
        serverSelectionTimeoutMS=30000
    )
    
    # Test the connection immediately
    client.admin.command('ping')
    logger.info("Successfully connected to MongoDB")
    
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    raise

db = client[os.getenv('DATABASE_NAME', '')]

# Collections
users_collection = db['users']
scans_collection = db['scans']
sni_collection = db['sni_hosts']

# Webhook configuration
PORT = int(os.getenv('PORT', 10000))
WEBHOOK_PATH = "/webhook"
WEBHOOK_SECRET = os.getenv('WEBHOOK_SECRET', '')
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '') + WEBHOOK_PATH

# Load SNI hosts into MongoDB if not already loaded
def load_sni_hosts():
    """Load SNI hosts into MongoDB if not already loaded."""
    if sni_collection.count_documents({}) > 0:
        return  # Already loaded

    if os.path.exists("sni.txt"):
        with open("sni.txt", "r") as file:
            country = None
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):  # Ignore empty lines and comments
                    if line.startswith("Country:"):
                        country = line.replace("Country:", "").strip()
                    elif country:
                        sni_collection.update_one(
                            {'country': country},
                            {'$addToSet': {'hosts': line}},
                            upsert=True
                        )

# Initialize SNI hosts
load_sni_hosts()

# === DATABASE FUNCTIONS ===
def add_user(user):
    """Add user to database if not exists"""
    users_collection.update_one(
        {'user_id': user.id},
        {'$set': {
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'join_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }},
        upsert=True
    )

def add_scan(user_id, scan_type, target, results):
    """Add a scan record to database"""
    scans_collection.insert_one({
        'user_id': user_id,
        'type': scan_type,
        'target': target,
        'results': results,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

def count_users():
    """Count the number of unique users"""
    return users_collection.count_documents({})

def get_sni_hosts(country):
    """Get SNI hosts for a specific country"""
    record = sni_collection.find_one({'country': country})
    return record['hosts'] if record else []

# === FORCE JOIN FUNCTIONALITY ===
async def is_member_of_channels(user_id: int, context: CallbackContext) -> bool:
    """Check if the user is a member of all required channels."""
    for channel in CONFIG['required_channels']:
        try:
            chat_member = await context.bot.get_chat_member(chat_id=f"@{channel}", user_id=user_id)
            if chat_member.status not in ["member", "administrator", "creator"]:
                return False
        except BadRequest:
            return False
    return True

async def send_force_join_message(update: Update):
    """Send force join message with buttons for all channels."""
    buttons = [
        [InlineKeyboardButton(f"Join {CONFIG['required_channels'][i]}", url=CONFIG['channel_links'][i])] 
        for i in range(len(CONFIG['required_channels']))
    ]
    reply_markup = InlineKeyboardMarkup(buttons)
    
    await update.message.reply_text(
        "🚨 You must join all required channels to use this bot.\n\n"
        "After joining, type /start again.",
        reply_markup=reply_markup
    )

# === SCANNING FUNCTIONS ===
def resolve_dns(host):
    """Resolve the host to an IP address."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.error:
        return False

def check_host(host, port):
    """Check if a host is reachable on a specific port and measure latency."""
    try:
        start_time = time.time()
        if port == 443:
            response = requests.get(f"https://{host}", timeout=10)
            latency = (time.time() - start_time) * 1000
            return True, latency
        elif port == 80:
            response = requests.get(f"http://{host}", timeout=10)
            latency = (time.time() - start_time) * 1000
            return True, latency
        else:
            socket.setdefaulttimeout(10)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            start_time = time.time()
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000
            return result == 0, latency
    except (requests.RequestException, socket.error) as e:
        logging.error(f"Error checking {host}: {e}")
        return False, 0

def check_host_with_retry(host, port, retries=2):
    """Check a host with retries to handle temporary failures."""
    for attempt in range(retries):
        is_working, latency = check_host(host, port)
        if is_working:
            return True, latency
        time.sleep(1)
    return False, 0

# === COMMAND HANDLERS ===
async def start(update: Update, context: CallbackContext):
    """Handle the /start command."""
    user = update.effective_user
    add_user(user)
    
    if not await is_member_of_channels(user.id, context):
        await send_force_join_message(update)
        return
    
    welcome_msg = (
        "𝗪𝗲𝗹𝗰𝗼𝗺𝗲 𝘁𝗼 𝗦𝗡𝗜/𝗛𝗢𝗦𝗧 𝗙𝗶𝗻𝗱𝗲𝗿 🔍!\n\n"
        "You can scan SNI or hosts by sending a txt file containing hosts, or you can choose a country, "
        "and I will provide the Hosts for that country."
    )
    await update.message.reply_text(welcome_msg)

async def scan_specific_host(update: Update, context: CallbackContext):
    """Scan a specific host provided by the user."""
    user = update.effective_user
    
    if not await is_member_of_channels(user.id, context):
        await send_force_join_message(update)
        return

    if not context.args:
        await update.message.reply_text("𝐏𝐥𝐞𝐚𝐬𝐞 𝐩𝐫𝐨𝐯𝐢𝐝𝐞 𝐚 𝐡𝐨𝐬𝐭 𝐭𝐨 𝐬𝐜𝐚𝐧. Example: `/scan www.who.int`")
        return

    host = context.args[0].strip()
    host = host.replace("http://", "").replace("https://", "").split("/")[0]

    await update.message.reply_text(f"⏳ 𝚂𝚌𝚊𝚗𝚗𝚒𝚗𝚐 {host}... 𝙿𝚕𝚎𝚊𝚜𝚎 𝚠𝚊𝚒𝚝.")

    is_working_443, latency_443 = check_host_with_retry(host, 443)
    is_working_80, latency_80 = check_host_with_retry(host, 80)

    if is_working_443 or is_working_80:
        latency = latency_443 if is_working_443 else latency_80
        result = f"✅ {host} is working on port {'443' if is_working_443 else '80'} (Latency: {latency:.2f} ms)"
    else:
        result = f"❌ {host} is NOT working on ports 443 and 80."

    # Save scan results
    add_scan(user.id, "single_host", host, result)
    await update.message.reply_text(result)

async def handle_document(update: Update, context: CallbackContext):
    """Handle file uploads and scan multiple hosts."""
    user = update.effective_user
    
    if not await is_member_of_channels(user.id, context):
        await send_force_join_message(update)
        return
    
    await update.message.reply_text("⏳ 𝚂𝚌𝚊𝚗𝚗𝚒𝚗𝚐 𝚑𝚘𝚜𝚝𝚜... 𝙿𝚕𝚎𝚊𝚜𝚎 𝚠𝚊𝚒𝚝.")

    file = await update.message.document.get_file()
    file_path = f"{file.file_id}.txt"
    await file.download_to_drive(file_path)
    
    working_hosts = []
    non_working_hosts = []
    
    with open(file_path, "r") as f:
        for line in f:
            host = line.strip()
            if not host:
                continue
            host = host.replace("http://", "").replace("https://", "").split("/")[0]
            
            if not resolve_dns(host):
                non_working_hosts.append(f"- {host}")
                continue
            
            is_working_443, latency_443 = check_host_with_retry(host, 443)
            is_working_80, latency_80 = check_host_with_retry(host, 80)
            
            if is_working_443 or is_working_80:
                latency = latency_443 if is_working_443 else latency_80
                working_hosts.append(f"- {host} (Latency: {latency:.2f} ms)")
            else:
                non_working_hosts.append(f"- {host}")
            
            time.sleep(1)
    
    response = []
    if working_hosts:
        response.append("⭑⭑★✪ 𝗪𝗼𝗿𝗸𝗶𝗻𝗴 𝗛𝗼𝘀𝘁𝘀/𝗦𝗡𝗜 ✪★⭑⭑\n\n")
        response.extend(working_hosts)
    if non_working_hosts:
        response.append("\n◉⦿◉ 𝗡𝗼𝗻 𝗪𝗼𝗿𝗸𝗶𝗻𝗴 𝗛𝗼𝘀𝘁𝘀/𝗦𝗡𝗜 ◉⦿◉\n\n")
        response.extend(non_working_hosts)
    
    # Save scan results
    add_scan(user.id, "file_upload", file_path, {
        'working_hosts': working_hosts,
        'non_working_hosts': non_working_hosts
    })
    
    await update.message.reply_text("\n".join(response))
    os.remove(file_path)

async def handle_generate_command(update: Update, context: CallbackContext):
    """Provide Zero Rated sites for a given country."""
    user = update.effective_user
    
    if not await is_member_of_channels(user.id, context):
        await send_force_join_message(update)
        return
    
    user_input = " ".join(context.args).strip()
    
    if not user_input:
        await update.message.reply_text("🏳️ 𝐏𝐥𝐞𝐚𝐬𝐞 𝐭𝐞𝐥𝐥 𝐦𝐞 𝐰𝐡𝐢𝐜𝐡 𝐜𝐨𝐮𝐧𝐭𝐫𝐲 𝐲𝐨𝐮 𝐰𝐚𝐧𝐭 𝐭𝐨 𝐠𝐞𝐭 𝐢𝐭𝐬 𝐙𝐞𝐫𝐨 𝐑𝐚𝐭𝐞𝐝 𝐬𝐢𝐭𝐞𝐬 𝐨𝐫 𝐒𝐍𝐈 𝐇𝐨𝐬𝐭𝐬.")
        return
    
    country = user_input.capitalize()
    hosts = get_sni_hosts(country)
    
    if hosts:
        await update.message.reply_text(f"🔍 𝚂𝚌𝚊𝚗𝚗𝚒𝚗𝚐 𝚂𝙽𝙸 𝙷𝚘𝚜𝚝𝚜 𝚏𝚛𝚘𝚖 {country}...")
        response = f"𝗭𝗲𝗿𝗼 𝗥𝗮𝘁𝗲𝗱 𝗦𝗶𝘁𝗲𝘀 𝗳𝗼𝗿 {country}:\n\n" + "\n".join(hosts)
        # Save the query
        add_scan(user.id, "country_query", country, {'hosts_count': len(hosts)})
    else:
        response = f"❌ 𝙉𝙤 𝙕𝙚𝙧𝙤 𝙍𝙖𝙩𝙚𝙙 𝙨𝙞𝙩𝙚𝙨 𝙛𝙤𝙪𝙣𝙙 𝙛𝙤𝙧 {country}."
    
    await update.message.reply_text(response)

# Function to broadcast a message to all users
async def broadcast(update: Update, context: CallbackContext):
    """Broadcast a message to all users (admin only)."""
    if update.effective_user.id not in CONFIG['admin_ids']:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    if not context.args:
        await update.message.reply_text("📢 ✨ Compose your broadcast message ✨\n\n"
                                        "Please provide the message you'd like to send to all users.\n"
                                        "You can include text, photos, or documents.\n\n"
                                        "❌ Type 'Cancel' to abort.")
        return

    # Preserve the formatting of the message
    message = update.message.text.replace("/broadcast", "").strip()
    if not message:
        await update.message.reply_text("❌ The broadcast message cannot be empty.")
        return

    users = users_collection.find({}, {'user_id': 1})
    success = 0
    failures = 0

    progress_message = await update.message.reply_text(f"📨 Broadcast initiated...\n\n"
                                                       f"📊 Total recipients: {users_collection.count_documents({})}\n"
                                                       f"⏳ Status: Processing...\n\n"
                                                       f"[░░░░░░░░░░] 0%")

    total_users = users_collection.count_documents({})
    update_interval = max(1, total_users // 10)

    for index, user in enumerate(users):
        try:
            await context.bot.send_message(chat_id=user['user_id'], text=message, parse_mode="Markdown")
            success += 1
        except Exception as e:
            logger.warning(f"Failed to send message to {user['user_id']}: {e}")
            failures += 1

        # Update progress periodically
        if (index + 1) % update_interval == 0 or index + 1 == total_users:
            progress = int((index + 1) / total_users * 100)
            progress_bar = '█' * (progress // 10) + '░' * (10 - progress // 10)
            await progress_message.edit_text(f"📨 Broadcast initiated...\n\n"
                                             f"📊 Total recipients: {total_users}\n"
                                             f"⏳ Status: Processing...\n\n"
                                             f"[{progress_bar}] {progress}%")

    await update.message.reply_text(f"📢 Broadcast completed!\n\n"
                                     f"✅ Sent: {success}\n"
                                     f"❌ Failed: {failures}\n\n"
                                     f"✨ Thank you for using the broadcast system!")

# Update the /stats command to allow only admins
async def stats(update: Update, context: CallbackContext):
    """Show bot statistics (admin only)."""
    if update.effective_user.id not in CONFIG['admin_ids']:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return

    user_count = count_users()
    scan_count = scans_collection.count_documents({})
    await update.message.reply_text(
        f"📊 Bot Statistics:\n"
        f"- Total Users: {user_count}\n"
        f"- Total Scans: {scan_count}"
        f"━━━━━━━━━━━━━━━━━━\n"
    )

async def how_to_use(update: Update, context: CallbackContext):
    """Show instructions on how to use the bot."""
    how_to_use_msg = (
        "💡 𝗛𝗼𝘄 𝘁𝗼 𝗨𝘀𝗲 ❔\n\n"
        "1. 𝗦𝘁𝗮𝗿𝘁 𝘁𝗵𝗲 𝗯𝗼𝘁 Type /start to begin.\n"
        "2. 𝗦𝗰𝗮𝗻 𝗮 𝘀𝗶𝗻𝗴𝗹𝗲 𝗵𝗼𝘀𝘁: Type /scan followed by the host you want to check.\n"
        "3. 𝗦𝗰𝗮𝗻 𝗺𝘂𝗹𝘁𝗶𝗽𝗹𝗲 𝗵𝗼𝘀𝘁𝘀 : Upload a `.txt` file with hosts to scan them.\n"
        "4. 𝗚𝗲𝗻𝗲𝗿𝗮𝘁𝗲 𝗰𝗼𝘂𝗻𝘁𝗿𝘆-𝗯𝗮𝘀𝗲𝗱 𝗵𝗼𝘀𝘁𝘀 : Use /generate followed by the country name.\n"
        "5. 𝗙𝗼𝗿 𝗵𝗲𝗹𝗽 : Type /contactus to reach the support team.\n\n"
        "✅ 𝙃𝙤𝙬 𝙩𝙤 𝙐𝙨𝙚 𝙩𝙝𝙚 𝘽𝙤𝙩❔\n\n"
        "Below is a must-watch video on how to use the Bot to avoid errors.\n\n"
        "💙 𝐑𝐞𝐦𝐞𝐦𝐛𝐞𝐫 𝐭𝐨 𝐒𝐮𝐛𝐬𝐜𝐫𝐢𝐛𝐞 𝐭𝐨 𝐨𝐮𝐫 𝐘𝐨𝐮𝐓𝐮𝐛𝐞 𝐂𝐡𝐚𝐧𝐧𝐞𝐥 𝐟𝐨𝐫 𝐒𝐮𝐩𝐩𝐨𝐫𝐭."
    )
    video_button = InlineKeyboardMarkup([
        [InlineKeyboardButton("Tᴜᴛᴏʀɪᴀʟ Cʟɪᴄᴋ Hᴇʀᴇ", url="https://youtu.be/BdCdYcSrL80?si=nz9LJ7fWgcQQ_BCl")]
    ])
    await update.message.reply_text(how_to_use_msg, reply_markup=video_button)

async def contact_us(update: Update, context: CallbackContext):
    """Provide contact information."""
    contact_info_msg = (
        "📞 ★彡( 𝕮𝖔𝖓𝖙𝖆𝖈𝖙 𝖀𝖘 )彡★ 📞\n\n"
        "📧 Eᴍᴀɪʟ: `freenethubbusiness@gmail.com`\n\n"
        "Fᴏʀ Aɴʏ Iꜱꜱᴜᴇꜱ, Bᴜꜱɪɴᴇꜱꜱ Dᴇᴀʟꜱ Oʀ IɴQᴜɪʀɪᴇꜱ, Pʟᴇᴀꜱᴇ Rᴇᴀᴄʜ Oᴜᴛ Tᴏ Uꜱ \n\n"
        "❗ *ONLY FOR BUSINESS AND HELP, DON'T SPAM!*"
    )
    
    keyboard = [[InlineKeyboardButton("📩 Mᴇꜱꜱᴀɢᴇ Aᴅᴍɪɴ", url="https://t.me/SILANDO")]]
    
    await update.message.reply_text(
        contact_info_msg,
        parse_mode="Markdown",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )



# === WEBHOOK SETUP ===
async def health_check(request):
    """Health check endpoint"""
    return web.Response(text="OK")

async def telegram_webhook(request):
    """Handle incoming webhook requests"""
    update = Update.de_json(await request.json(), application.bot)
    await application.update_queue.put(update)
    return web.Response(text="OK")

def main():
    """Run the bot"""
    global application
    application = Application.builder().token(CONFIG['token']).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan_specific_host))  
    application.add_handler(CommandHandler("generate", handle_generate_command))
    application.add_handler(MessageHandler(filters.Document.MimeType("text/plain"), handle_document))
    application.add_handler(CommandHandler("howtouse", how_to_use))
    application.add_handler(CommandHandler("stats", stats))  # Updated stats command
    application.add_handler(CommandHandler("contactus", contact_us))
    application.add_handler(CommandHandler("broadcast", broadcast))  # Updated /broadcast command

    # Start the bot with webhook if running on Render
    if os.getenv('RENDER'):
        application.run_webhook(
            listen="0.0.0.0",
            port=PORT,
            url_path=WEBHOOK_PATH,
            webhook_url=WEBHOOK_URL
        )
    else:
        application.run_polling()

if __name__ == "__main__":
    main()
