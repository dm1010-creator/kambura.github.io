import streamlit as st
import smtplib, os, json, csv
from email.mime.text import MIMEText
from datetime import datetime
import pandas as pd

# --- Configuration ---
SENDER = "dougiemutua@outlook.com"
APP_PASSWORD = "your_outlook_app_password"  # Outlook app password
ORDERS_EMAIL = "GroupNomad@outlook.com"
ORDERS_DIR = "orders"  # folder for Git logs

# Ensure orders folder exists
os.makedirs(ORDERS_DIR, exist_ok=True)

# --- Email Sender ---
def send_email(subject, body, recipient, customer_email=None):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER
    msg['To'] = recipient

    with smtplib.SMTP("smtp.office365.com", 587) as server:
        server.starttls()
        server.login(SENDER, APP_PASSWORD)
        server.send_message(msg)

    # --- Auto-reply to customer ---
    if customer_email:
        confirmation = f"""
        Hello {body.splitlines()[2].split(': ')[1]},

        Thank you for your {subject.lower()} with Rustic Garden 🌿.
        We’ve received the following details:

        {body}

        Our team will confirm shortly.

        Warm regards,  
        Rustic Garden
        """
        reply_msg = MIMEText(confirmation)
        reply_msg['Subject'] = "Confirmation – " + subject
        reply_msg['From'] = SENDER
        reply_msg['To'] = customer_email

        with smtplib.SMTP("smtp.office365.com", 587) as server:
            server.starttls()
            server.login(SENDER, APP_PASSWORD)
            server.send_message(reply_msg)

# --- Order Logger (JSON + CSV) ---
def log_order(order_type, data):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_name = f"{timestamp}_{order_type.lower().replace(' ', '_')}"

    # JSON log
    json_path = os.path.join(ORDERS_DIR, base_name + ".json")
    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(data, jf, indent=4)

    # CSV log (append mode)
    csv_path = os.path.join(ORDERS_DIR, "orders.csv")
    file_exists = os.path.isfile(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(cf, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# --- Streamlit App ---
st.set_page_config(page_title="Rustic Garden Orders", page_icon="🌿", layout="centered")
st.title("🌿 Rustic Garden – Coffee & Event Orders")

menu = st.sidebar.radio("Navigation", ["Customer Portal", "Admin Dashboard"])

# --- CUSTOMER PORTAL ---
if menu == "Customer Portal":
    choice = st.radio("What would you like to do?", ["Order Coffee ☕", "Book Grounds 🌳"])

    if choice == "Order Coffee ☕":
        coffee_type = st.selectbox("Choose coffee type:", ["Espresso", "Latte", "Cappuccino", "Americano"])
        size = st.radio("Select size:", ["Small", "Medium", "Large"])
        extras = st.multiselect("Extras:", ["Sugar", "Milk", "Caramel Syrup", "Vanilla Syrup"])
        customer_name = st.text_input("Your name")
        customer_email = st.text_input("Your email")

        if st.button("Submit Coffee Order"):
            order_data = {
                "timestamp": str(datetime.now()),
                "type": "Coffee Order",
                "name": customer_name,
                "email": customer_email,
                "coffee_type": coffee_type,
                "size": size,
                "extras": ", ".join(extras) if extras else "None"
            }

            order_text = "\n".join([f"{k}: {v}" for k, v in order_data.items()])
            send_email("Coffee Order", order_text, ORDERS_EMAIL, customer_email)
            log_order("Coffee Order", order_data)

            st.success("✅ Your coffee order has been placed! You’ll also receive a confirmation email.")

    elif choice == "Book Grounds 🌳":
        event_date = st.date_input("Select date")
        event_time = st.time_input("Select time")
        people = st.number_input("Number of people", min_value=1, step=1)
        event_type = st.text_input("Event type (Birthday, Corporate, Casual, etc.)")
        customer_name = st.text_input("Your name")
        customer_email = st.text_input("Your email")

        if st.button("Book Grounds"):
            booking_data = {
                "timestamp": str(datetime.now()),
                "type": "Grounds Booking",
                "name": customer_name,
                "email": customer_email,
                "date": str(event_date),
                "time": str(event_time),
                "people": people,
                "event_type": event_type
            }

            booking_text = "\n".join([f"{k}: {v}" for k, v in booking_data.items()])
            send_email("Grounds Booking", booking_text, ORDERS_EMAIL, customer_email)
            log_order("Grounds Booking", booking_data)

            st.success("✅ Your booking request has been sent! You’ll also receive a confirmation email.")

# --- ADMIN DASHBOARD ---
elif menu == "Admin Dashboard":
    st.header("📊 Order Management Dashboard")

    csv_path = os.path.join(ORDERS_DIR, "orders.csv")
    if os.path.isfile(csv_path):
        df = pd.read_csv(csv_path)
        st.dataframe(df, use_container_width=True)

        st.download_button(
            label="⬇ Download Orders as CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name="orders_export.csv",
            mime="text/csv"
        )
    else:
        st.info("No orders have been placed yet.")
