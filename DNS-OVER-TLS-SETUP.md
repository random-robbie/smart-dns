# DNS-over-TLS Setup Guide

SmartDNS Proxy now supports DNS-over-TLS (DoT) on port 853, allowing you to use Private DNS on Android and other devices.

## Quick Start

The DNS-over-TLS server is now running on your server at port 853.

## Setting Up Private DNS on Android

### Step 1: Export the Certificate from the Server

Run this command on your server to copy the certificate to a location you can access:

```bash
docker cp smartdns:/data/certs/dns.crt ~/dns.crt
```

### Step 2: Transfer Certificate to Your Phone

Transfer the `dns.crt` file to your phone using one of these methods:
- Email it to yourself
- Use a file sharing app (Google Drive, Dropbox, etc.)
- Transfer via USB
- Use ADB: `adb push ~/dns.crt /sdcard/Download/`

### Step 3: Install Certificate on Your Phone

1. Open **Settings** on your Android phone
2. Go to **Security** (or **Security & Privacy**)
3. Tap **Encryption & credentials** (or **More security settings**)
4. Tap **Install a certificate** or **Install from storage**
5. Select **CA certificate** (not VPN & app user certificate)
6. Tap **Install anyway** if warned
7. Navigate to and select the `dns.crt` file you transferred

### Step 4: Enable Private DNS

1. Open **Settings**
2. Go to **Network & internet** → **Private DNS**
3. Select **Private DNS provider hostname**
4. Enter your server's IP address: `192.168.1.82`
5. Tap **Save**

Your phone will now connect to SmartDNS using encrypted DNS-over-TLS!

## Verifying It Works

After setup:
1. Open Deliveroo or any app on your phone
2. Check the SmartDNS web interface at http://192.168.1.82:8080
3. Go to **Request Logs** tab
4. You should now see DNS requests from your phone appearing in the logs

All DNS queries from your phone will now go through your SmartDNS proxy, including apps like Deliveroo that were previously bypassing it.

## Testing DNS-over-TLS

You can test DNS-over-TLS from the command line using `kdig` (from knot-dnsutils package):

```bash
# Install kdig
sudo apt-get install knot-dnsutils  # Debian/Ubuntu
# or
brew install knot  # macOS

# Test DNS-over-TLS
kdig -d @192.168.1.82 +tls example.com
```

## Troubleshooting

### "Couldn't validate connection" on Android

This usually means:
1. The certificate wasn't installed correctly - try reinstalling it
2. The server IP address is wrong - double-check you entered `192.168.1.82`
3. Port 853 is blocked by a firewall
4. The SmartDNS container isn't running - check with `docker logs smartdns`

### Certificate Not Installing

- Make sure you select **CA certificate** (not VPN & app user certificate)
- Try using a different method to transfer the file
- Make sure the file hasn't been corrupted during transfer

### DNS Queries Still Not Appearing

- Check Private DNS is enabled: Settings → Network & internet → Private DNS
- Make sure it shows "Private DNS provider hostname" with your server IP
- Restart your phone after installing the certificate
- Check SmartDNS logs: `docker logs smartdns -f`

## Security Notes

- This uses a self-signed certificate, which is secure for your private network
- The certificate is valid for 10 years
- All DNS traffic between your phone and server is encrypted
- You need to install the certificate on each device that will use Private DNS

## Regenerating Certificates

If you need to regenerate certificates:

```bash
docker exec smartdns sh /app/generate-certs.sh
docker restart smartdns
```

Then reinstall the new certificate on your devices.
