const conn = require('../mariadb');
const {StatusCodes} = require('http-status-codes'); // status code 모듈 
const jwt = require('jsonwebtoken'); // jwt 모듈
const crypto = require('crypto'); // crypto 모듈 : 암호화 
const dotenv = require('dotenv');
dotenv.config(); 


const join = (req,res) => {
    const {email, password} = req.body; 


    let sql = 'INSERT INTO users (email, password, salt) VALUES (?, ?, ?)'; 

//회원가입 시 비밀번호를 암호화해서 암호화된 비밀번호 & salt 값을 같이 저장
const salt = crypto.randomBytes(10).toString('base64');
    const hashPassword = crypto.pbkdf2Sync(password, salt, 10000, 10, 'sha512').toString('base64')

// 로그인 시, 이메일&비밀번호 (날 것) => salt값 꺼내서 비밀번호 암호화 해보고 
// => DB 비밀번호랑 비교 
    let values = [email, hashPassword, salt]; 
    conn.query(sql, values, 
        (err, results) => { 
            if(err) { 
                console.log(err); 
                return res.status(StatusCodes.BAD_REQUEST).end(); // BAD REQUEST 
            } 

            res.status(StatusCodes.CREATED).json(results); // SUCCEED 
        }
    )
}


const login = (req,res) => { 
    const {email, password} = req.body;

    let sql = 'SELECT * FROM users WHERE email = ?'; 

    conn.query(sql, email, 
        (err, results) => { 
            if(err) { 
                console.log(err); 
                return res.status(StatusCodes.BAD_REQUEST).end(); // BAD REQUEST 
            } 

            const loginUser = results[0]; 
            if (loginUser && loginUser.password == password) { 
                // 토큰 발행
                const token = jwt.sign({ 
                    email : loginUser.email
                }, process.env.PRIVATE_KEY, {
                    expiresIn : '5m', 
                    issuer : "songa"
                }
            )

            // 토큰 쿠키에 담기
            res.cookie("token", token, { 
                httpOnly : true
            });
            console.log(token);

            return res.status(StatusCodes.OK).json(results);
        } else { 
            return res.status(StatusCodes.UNAUTHORIZED).end() // 401 : Unauthorized  //  403 : Forbidden (접근 권리 없음)        
            }

        }
    )
}


const passwordResetRequest = (req,res) => { 
    const {email} = req.body;

    let sql = 'SELECT * FROM users WHERE email = ?'; 

    conn.query(sql, email, 
        (err, results) => { 
            if(err) { 
                console.log(err); 
                return res.status(StatusCodes.BAD_REQUEST).end(); // BAD REQUEST 
            } 

            // 이메일로 유저가 있는지 찾아본다! 
            const user = results[0]; 
            if(user) { 
                return res.status(StatusCodes.OK).json({
                    email : email // json으로 온 이메일이 passwordReset으로 전달될 수 있음
                });
            } else { 
                return res.status(StatusCodes.UNAUTHORIZED).end();
            }
        }
)}

const passwordReset =  (req,res) => { 
    const {password, email} = req.body;

    let sql = 'UPDATE users SET password=? WHERE email=?'; 
    let values = [password, email] // 여기서 email은 비밀번호 초기화 요청에서 받은 email이 들어가야 한다. 

    conn.query(sql, values, 
        (err, results) => { 
            if(err) { 
                console.log(err); 
                return res.status(StatusCodes.BAD_REQUEST).end(); // BAD REQUEST 
            } 
                if(results.affectedRows === 0) {
                    return res.status(StatusCodes.BAD_REQUEST).end(); 
                } else { 
                    return res.status(StatusCodes.OK).json(results);
                }
        }   
        )
};


module.exports = {      // 여러 모듈들을 export 할 때는 JSON으로
    join, 
    login, 
    passwordResetRequest, 
    passwordReset
}