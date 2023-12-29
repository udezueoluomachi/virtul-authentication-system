// domain name user-authentication.virtul.net
require("dotenv").config();
const http = require("http");
const mysql = require("mysql");
const {parse} = require("querystring");
const nodemailer = require("nodemailer");
const {
    createCipheriv,
    createDecipheriv,
    scryptSync
} = require("crypto");
const {Buffer} = require("buffer");
const { google } = require("googleapis");

const OAuth2 = google.auth.OAuth2;
const oauth2Client = new OAuth2(process.env.CLIENT_ID, process.env.CLIENT_SECRET , "https://developers.google.com/oauthplayground");

oauth2Client.setCredentials({
    refresh_token: process.env.REFRESH_TOKEN
});

const accessToken = oauth2Client.getAccessToken();

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
         type: "OAuth2",
         user: "oluomachi.famfinance@gmail.com", 
         clientId: process.env.CLIENT_ID,
         clientSecret: process.env.CLIENT_SECRET,
         refreshToken: process.env.REFRESH_TOKEN,
         accessToken: accessToken
    }
});

const algorithm = process.env.ENCRYPTION_ALGORITHM , password = process.env.ENCRYPTION_PASSWORD;

const key = scryptSync(password, 'salt', 24);

const iv = Buffer.alloc(16, 0);
//remember to add , obfustication , minimalization and more security measures to the production base

let con = mysql.createConnection({
    host : process.env.MYSQL_HOST,
    user : process.env.MYSQL_USER,
    password : process.env.MYSQL_PASSWORD,
    database : process.env.MYSQL_DATABASE
});

function encrypt(data) {
    let cipher = createCipheriv(algorithm , key , iv);
    let encryptedData = cipher.update(data, "utf8" , "hex");
    encryptedData += cipher.final("hex");
    return encryptedData;
}
function decrypt(data) {
    let decipher = createDecipheriv(algorithm , key , iv);
    let decryptedData = decipher.update(data , "hex" , "utf8");
    decryptedData += decipher.final("utf8");
    return decryptedData;
}

const random_verification_code = function (e) {
    let generated_value = [];
    for (let i = 1; i <= e; i++) {
        generated_value.push(Math.floor(Math.random() * 10));
    }
    return parseInt(generated_value.join(""));
};

const generate_wallet_address = function() {
    const arr_of_characters = "QWERTYUIOPLKJHGFDSAZXCVBNMqwertyuiopasdfghjklzxcvbnm";
    let generated_charaters = [];
    for (let i = 0; i < arr_of_characters.length;) {
        generated_charaters.push(arr_of_characters[Math.floor(Math.random() * arr_of_characters.length)]);
        i++;
    }
    return generated_charaters.join('');
};
const port = process.env.PORT  || 4000;

http.createServer((req , res) => {
    try {
        if(req.headers.origin === process.env.ALLOWED_ORIGIN) {
            res.writeHead(200,{
                "Access-Control-Allow-Origin"       : process.env.ALLOWED_ORIGIN,
                "Acess-Control-Allow-Methods"       : "OPTIONS, POST, GET",
                "Access-Control-Max-Age"            : 2592000,
                "Access-Control-Request-Headers"    : "Content-Type"
            })
            if(req.method === "POST"){
                let req_body = "" , qData , email_address , password , request_name , verification_code;
        
                req.on("data", data => req_body += data);
        
                req.on("end", () => {
                   qData = parse(req_body);
                   email_address = qData.email_address;
                   password = qData.password;
                   let stage = qData.stage;
                   request_name = qData.request_name;
                   verification_code = qData.verification_code;
                   if(email_address && password && request_name === "registration-form") {
                       append_user(email_address,password,random_verification_code(5),generate_wallet_address());
                   }
                   if(email_address && password && request_name === "login-form") {
                       log_user(email_address,password);
                   }
                   if(email_address && password  && verification_code && request_name === "email-verification-form") {
                       verify_email(email_address , password , verification_code);
                   }
                   if(email_address && password && request_name === "delete-account"){
                        password = encrypt(password);
                        let sql = `SELECT email_address FROM users WHERE email_address = ? AND password = ? LIMIT 1`;
                        let values = [email_address , password];
                        con.query(sql , values , (err , result) => {
                            if(err) throw err;
                            if(result.length > 0) {
                                end_con();
                                let sql = `DELETE FROM users WHERE email_address = ? AND password = ?`;
                                let values = [email_address , password];
                                con.query(sql , values , (err , result , fields) => {
                                    if(err) throw err;
                                    end_con();
                                    mail(decrypt(email_address) , "Account Deleted Successfully" , `
                                        <div style="color: rgb(20, 20, 20);">
                                            <div style="padding: 25px 0; width:100%; border-bottom: 2px solid #b1b1b1b6; display: flex; justify-content: center; align-items: center; margin: auto;" >
                                                <img src="https://udezueoluomachi.github.io/virtul/images/logo.png" align="center" alt="virtul Inc" width="120px" style="display: block;">
                                            </div>
                                            <div>
                                                <h1>Account Deletion Successful</h1>
                                            </div>
                                            <div style="padding: 10px;">
                                                <p>Dear user , you have successfully deleted your virtul account permanently and none of your data is left with us. Thank you for using virtul.
                                                <p>Regards;<br/>Team virtul</p>
                                            </div>
                                            <footer>
                                                <p style="text-align: center; color: #5e5e5e;">
                                                    <small>virtul Inc. &copy; ${new Date().getFullYear()} All rights reserved.</small>
                                                </p>
                                            </footer>
                                        </div>
                                    `).catch(console.error);
                                    res.write("success");
                                    res.end();
                                })
                            }
                            else {
                                end_con();
                                res.write("wrong-password");
                                res.end();
                            }
                        })
                   }
                   if(email_address && password && request_name === "resend-verification-code") {
                        resend_verification_code(email_address , random_verification_code(5));
                    }
                   if(email_address && request_name === "recovery-form") {
                        email_address = encrypt(email_address);
                        if(stage == 1 ) {
                            //checking email existense
                            let sql = `SELECT email_address FROM users WHERE email_address = ? LIMIT 1`;
                            let value = [email_address];
                            con.query(sql , value , (err , result) => {
                                if(err) throw err;
                                if(result.length > 0) {
                                    end_con();
                                    resend_verification_code(email_address , random_verification_code(5));
                                }
                                else {
                                    end_con();
                                    res.write("no bro");
                                    res.end();
                                }
                            })
                        }
                        if(stage == 2 && verification_code) {
                            let sql = `SELECT verification_code from users WHERE email_address = ? AND verification_code = ? LIMIT 1`;
                            let values = [email_address , verification_code];
                            con.query(sql , values , (err , result) => {
                                if(err) throw err;
                                if(result.length > 0) {
                                    end_con();
                                    res.write(JSON.stringify({resolvement : true}));
                                    res.end();
                                }
                                else {
                                    end_con();
                                    res.write(JSON.stringify({resolvement : false}));
                                    res.end();
                                }
                            });
                        }
                        if(stage == 3 && password) {
                            password = encrypt(password);
                            let sql = `UPDATE users SET password = ? WHERE email_address = ?`;
                            let values = [password , email_address];
                            con.query(sql , values , (err , result , fields) => {
                                if(err) throw err;
                                end_con();
                                //log user
                                res.write(`${JSON.stringify({
                                    email_address : email_address,
                                    password : password,
                                    verified_email : 1
                                })}`);
                                res.end();
                            })
                        }
                    }
                });
            }
            else {
                res.write("Hello world!");
                res.end();
            }
        }
        else {
            res.writeHead(403,{
                "Access-Control-Allow-Origin"       : process.env.ALLOWED_ORIGIN
            });
            res.write("sorry");
            res.end();
        }
    
        function resend_verification_code(email , verification_code) {
            let sql = `UPDATE users SET verification_code = ? WHERE email_address = ?`;
            con.query(sql , [verification_code , email] , (err , result , fields) => {
                if(err) throw err;
                end_con();
                mail_verification_code(verification_code , decrypt(email)).catch(console.error);
                res.write("resent-code");
                res.end();
            });
        }
        async function welcome_mail(email) {
    
            let info = await transporter.sendMail({
                from : `virtul Inc <${process.env.EMAIL_USER}>`,
                to : email,
                subject : "Welcome to virtul",
                html : `
                <div style="color: rgb(20, 20, 20);">
                    <div style="padding: 25px 0; width:100%; border-bottom: 2px solid #b1b1b1b6; display: flex; justify-content: center; align-items: center; margin: auto;" >
                        <img src="https://udezueoluomachi.github.io/virtul/images/logo.png" align="center" alt="virtul Inc" width="120px" style="display: block;">
                    </div>
                    <div>
                        <h1>Welcome To virtul</h1>
                    </div>
                    <div style="padding: 10px;">
                        <p>Dear user , we are delighted that you have joined the virtul comminity. Explore the world of crypto stock trading with virtul.</p>
                        <p>Regards;<br/>Team virtul</p>
                    </div>
                    <footer>
                        <p style="text-align: center; color: #5e5e5e;">
                            <small>virtul Inc. &copy; ${new Date().getFullYear()} All rights reserved.</small>
                        </p>
                    </footer>
                </div>
                `
            })
        }
        async function mail(email , subject , html) {
        
            let info = await transporter.sendMail({
                from : `'virtul inc' <${process.env.EMAIL_USER}>`,
                to : email,
                subject : subject,
                html : html
            })
        }
    
        async function mail_verification_code(code , email) {
            let info = await transporter.sendMail({
                from : `virtul Inc <${process.env.EMAIL_USER}>`,
                to : email,
                subject : "Verify your email address to proceed",
                html : `
                    <div style="color: rgb(20, 20, 20);">
                        <div style="padding: 25px 0; width:100%; border-bottom: 2px solid #b1b1b1b6; display: flex; justify-content: center; align-items: center; margin: auto;" >
                            <img src="https://udezueoluomachi.github.io/virtul/images/logo.png" align="center" alt="virtul Inc" width="120px" style="display: block;">
                        </div>
                        <div>
                            <h1>Verify Email Address</h1>
                        </div>
                        <div style="padding: 10px;">
                            <p>Thanks for choosing virtul, please verify your email address using the verification code below;</p>
                            <br/>
                            <br/>
                            <p>Verification code : <big><b>${code}</b></big></p>
                            <br/>
                            <p>Use this code to verify your email address and continue your signup process. Do not share this code with anyone.</p>
                        </div>
                        <footer>
                            <p style="text-align: center; color: #5e5e5e;">
                                <small>virtul Inc. &copy; ${new Date().getFullYear()} All rights reserved.</small>
                            </p>
                        </footer>
                    </div>
                `
            })
        }
        function log_user(email , password) {
            email = encrypt(email);
            password = encrypt(password);
    
            let sql = `SELECT email_address FROM users WHERE email_address = ? LIMIT 1`;
            con.query(sql , [email], (err , result) => {
                if (err) throw err;
                if(result.length > 0) {
                    end_con();
                    //check password
                    let sql = `SELECT email_address , password , verified_email FROM users WHERE email_address = ? AND password = ? LIMIT 1`;
                    con.query(sql , [email , password] , (err , result) => {
                        if(err) throw err;
                        if(result.length > 0) {
                            end_con();
                            //log user
                            res.write(`${JSON.stringify({
                                email_address : result[0].email_address,
                                password : result[0].password,
                                verified_email : result[0].verified_email
                            })}`);
                            res.end();
                        }
                        else {
                            end_con();
                            //wrong password
                            res.write(`${JSON.stringify({
                                password : 'wrong'
                            })}`);
                            res.end();
                        }
                    })
                }
                else {
                    end_con();
                    res.write(`${JSON.stringify({
                        email_address : 'wrong'
                    })}`);
                    res.end();
                }
            });
        }
        //remember to work with nodemailer and nodemon
        function verify_email(email , password , verification_code) {
            let sql = `SELECT verification_code from users WHERE email_address = ? AND password = ? AND verification_code = ? LIMIT 1`;
            let values = [email , password , verification_code];
            con.query(sql , values , (err , result) => {
                if(err) throw err;
                if(result.length > 0) {
                    end_con();
                    //is correct
                    let sql = `UPDATE users SET verified_email = ? WHERE email_address = ? AND password = ? AND verification_code = ?`;
                    con.query(sql , [1 , email , password , verification_code] , (err , result , fields ) => {
                        if (err) throw err;
                        else {
                            welcome_mail(decrypt(email)).catch(console.error);
                            res.write(`${JSON.stringify({
                                email_address : email,
                                password : password,
                                verified_email : 1
                            })}`);
                            res.end();
                        }
                        end_con();
                    });
                }
                else {
                    end_con();
                    res.write(`${JSON.stringify({
                        email_address : email,
                        password : password,
                        verified_email : 0
                    })}`);
                    res.end();
                }
            })
        }
        function append_user(email,password,verification_code,wallet_address) {
            email = encrypt(email);
            password = encrypt(password);
            // remember to tell the user that an account already exists for the email address
            let sql = `SELECT password , verified_email FROM users WHERE email_address = ? LIMIT 1`;
            let values = [email];
            con.query(sql , values , (err , result) => {
                if(err) throw err;
                if(result.length > 0) {
                    end_con();
                    if(result[0].password == password) {
                        if(result[0].verified_email == 0) {
                            res.write(`${JSON.stringify({
                                email_address : email,
                                password : password,
                                verified_email : 0
                            })}`);
                        } else {
                            res.write(`${JSON.stringify({
                                email_address : email,
                                password : password,
                                verified_email : 1
                            })}`);
                        }
                        res.end();
                    }
                    else {
                        //warn user that account exists and dont do anything.
                        res.write("account_exists");
                        res.end();
                    }
                }
                else {
                    end_con();
                    //append user
    
                    mail_verification_code(verification_code , decrypt(email)).catch(console.error);
    
                    let sql = `INSERT INTO users (email_address , password , stock_balance , fiat_balance , pending_withdrawal , wallet_address , transaction_records_db , pending_withdrawal_db , verification_code , verified_email , notification_db) VALUES (? , ? , ? , ? , ? , ? , ? , ? , ? , ? , ?)`;
                    values = [email , password , 0.0 , 0.0 , 0.0 , wallet_address , JSON.stringify([]), JSON.stringify([]), verification_code, 0 , JSON.stringify([])];
                    con.query(sql , values , (err , result , fields) => {
                        if (err) throw err;
                        end_con();
                        res.write(`${JSON.stringify({
                            email_address : email,
                            password : password,
                            verified_email : 0
                        })}`)
                        res.end();
                    });
                }
            });
        }
    }
    catch(error) {
        console.error(error)
        return res.end("something went wrong")
    }
})
.listen(port, () => console.log(`server running on port : ${port}`));

function end_con() {
    con.end();
    con = mysql.createConnection({
        host : process.env.MYSQL_HOST,
        user : process.env.MYSQL_USER,
        password : process.env.MYSQL_PASSWORD,
        database : process.env.MYSQL_DATABASE
    });
}