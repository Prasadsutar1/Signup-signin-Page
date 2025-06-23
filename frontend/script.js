const container = document.getElementById("container");
const registerBtn = document.getElementById("register");

const loginBtn = document.getElementById("login");

registerBtn.addEventListener("click", () => {
    container.classList.add("active");
});

loginBtn.addEventListener("click", () => {
    container.classList.remove("active");
});

function toggle() {
    container.classList.remove("active");
}
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const form2 = document.getElementById('signup-form');
const responseDiv2 = document.getElementById('response2');

form2.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name2 = document.getElementById('name2').value;
    const email2 = document.getElementById('email2').value;
    const password2 = document.getElementById('password2').value;
    if(!email2){
        responseDiv2.innerHTML = "Please enter email";
        sleep(2000).then(() => responseDiv2.innerHTML = "");
        return;
    }
    if (!password2) {
        responseDiv2.innerHTML = "Please enter password";
        sleep(2000).then(() => responseDiv2.innerHTML = "");
        return;
    }

    console.log("done");
    try {
        const response2 = await fetch('https://signup-signin-page-three.vercel.app/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                name: name2,
                email: email2,
                password: password2
            })
        });

        if (response2.ok) {
            const data = await response2.json();
            const login2Btn = document.getElementById("login2");
            try {
                if (data.message == "You are signed up") {
                    responseDiv2.innerHTML = "&#10004; Signed up";
                    sleep(1000).then(() => {
                        responseDiv2.innerHTML = "";
                        toggle();
                    });
                }
                else {
                    if (data.message.errorResponse.code == 11000) {
                        responseDiv2.innerHTML = "User has Already Signed up";
                        sleep(1000).then(() => {
                            responseDiv2.innerHTML = "";
                            toggle();
                        });
                    }
                }
            }
            catch (error) {
                responseDiv2.innerHTML = `Error: ${error.message}`;
            }

        } else {
            responseDiv2.innerHTML = `Error: ${response2.status} ${response2.statusText}`;
        }
    } catch (error) {
        responseDiv2.innerHTML = `Error: ${error.message}`;
    }
});


//signin pAGE  
const form = document.getElementById('signin-form');
const responseDiv = document.getElementById('response');

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    if(!email){
        responseDiv.innerHTML = "Please enter email";
        sleep(2000).then(() => responseDiv.innerHTML = "");
        return;
    }
    if (!password) {
        responseDiv.innerHTML = "Please enter password";
        sleep(2000).then(() => responseDiv.innerHTML = "");
        return;
    }
    try {
        const response = await fetch('https://signup-signin-page-three.vercel.app/signin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });
        if (response.ok) {
            const data = await response.json();
            responseDiv.innerHTML = data.message;
            sleep(2000).then(() => responseDiv.innerHTML = "");

        } else {
            const data = await response.json();
            responseDiv.innerHTML = `Error: ${data.message}`;
        }
    } catch (error) {
        responseDiv.innerHTML = `Errorr: ${error.message}`;
    }
});
