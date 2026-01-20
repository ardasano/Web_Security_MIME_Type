<!DOCTYPE html>
<html lang="tr">
  <head>
    <meta charset="UTF-8" />
    <title>Web_Security_MIME_Type</title>
    <style>
      body {
        font-family: sans-serif;
        background: linear-gradient(
          120deg,
          #84fab0 0%,
          #8fd3f4 100%
        ); /* Canli Renkler */
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
      }
      .kutu {
        background: white;
        padding: 40px;
        border-radius: 15px;
        box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
        text-align: center;
        width: 350px;
      }
      h2 {
        color: #333;
      }
      .btn {
        background-color: #007bff;
        color: white;
        padding: 10px 20px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-size: 16px;
      }
      .btn:hover {
        background-color: #0056b3;
      }
      .sonuc-kutu {
        margin-top: 20px;
        padding: 10px;
        border-radius: 5px;
        font-weight: bold;
        color: white;
      }
      .yesil {
        background-color: #28a745;
      }
      .kirmizi {
        background-color: #dc3545;
      }
    </style>
  </head>
  <body>
    <div class="kutu">
      <h2>🛡️ Dosya Yükleme</h2>
      <p>Magic Byte Analizi Aktif</p>

      <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" required />
        <br /><br />
        <button type="submit" class="btn">Kontrol Et ve Yükle</button>
      </form>

      {% if mesaj %}
      <div class="sonuc-kutu {{ renk }}">{{ mesaj }}</div>
      {% endif %}
    </div>

  </body>
</html>
