import 'dotenv/config'
import express from "express"
import axios from "axios"
import cors from "cors"
import pool from "./db.js"
import bcrypt from "bcrypt"
import rateLimit from "express-rate-limit"
import helmet from "helmet"
import jwt from "jsonwebtoken"
import validator from "validator"
import multer from "multer"
import { v2 as cloudinary } from "cloudinary"

// 🔥 CONFIG CLOUDINARY (logo após imports)
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
})

const upload = multer({ dest: "uploads/" })

// 👇 PRIMEIRO CRIA O APP
const app = express()

// 👇 DEPOIS USA OS MIDDLEWARES
app.use(helmet())

app.use(cors({
  origin: "http://localhost:5174"
}))

app.use(express.json())

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: "Muitas tentativas de login"
})



const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // limite por IP
  message: "Muitas requisições, tente novamente depois."
})



app.use(limiter)





// 📌 CRIAR ALUNO
app.post('/alunos', verificarToken, async (req, res) => {
  try {
    const { nome, email, telefone, curso, valor, vencimento } = req.body

    const result = await pool.query(
      `INSERT INTO alunos (nome, email, telefone, curso, valor, vencimento)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [nome, email, telefone, curso, valor, vencimento]
    )

    res.json(result.rows[0])
  } catch (err) {
    console.error(err)
    res.status(500).send('Erro interno do servidor')
  }
})

// 📌 LISTAR ALUNOS
app.get('/alunos', verificarToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM alunos ORDER BY id DESC')
    res.json(result.rows)
  } catch (err) {
    console.error(err)
    res.status(500).send('Erro interno do servidor')
  }
})

// 💳 ATUALIZAR PAGAMENTO (CORRIGIDO)
app.put('/alunos/:id/pagamento', verificarToken, async (req, res) => {
  const { id } = req.params
  const { pagou, mes_pagamento } = req.body

  try {
    await pool.query(
      'UPDATE alunos SET pagou = $1, mes_pagamento = $2 WHERE id = $3',
      [pagou, mes_pagamento, id]
    )

    res.send('OK')
  } catch (err) {
    console.error(err)
    res.status(500).send('Erro interno do servidor')
  }
})

// 📆 ATUALIZAR AULA (CORRIGIDO)
app.put('/alunos/:id/aula', verificarToken, async (req, res) => {
  const { id } = req.params
  const { fezAula, semana_aula } = req.body

  try {
    await pool.query(
      'UPDATE alunos SET fez_aula = $1, semana_aula = $2 WHERE id = $3',
      [fezAula, semana_aula, id]
    )

    res.send('OK')
  } catch (err) {
    console.error(err)
    res.status(500).send('Erro interno do servidor')
  }
})


app.post('/motivos', verificarToken, async (req, res) => {
  const { aluno_id, mes, tipo, motivo } = req.body;

  await pool.query(
    'INSERT INTO motivos (aluno_id, mes, tipo, motivo) VALUES ($1, $2, $3, $4)',
    [aluno_id, mes, tipo, motivo]
  );

  res.send('OK');
});
app.get('/motivos/:aluno_id', verificarToken, async (req, res) => {
  const { aluno_id } = req.params;

  try {
    const result = await pool.query(
      'SELECT * FROM motivos WHERE aluno_id = $1 ORDER BY id DESC',
      [aluno_id]
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Erro interno do servidor');
  }
});


const SECRET = process.env.JWT_SECRET; // depois melhora isso

function verificarToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send("Token não enviado");
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).send("Token inválido");
  }
}


app.post('/register', async (req, res) => {
  try {
    const { email, senha } = req.body

    // 🔒 VALIDAÇÃO
    if (!email || !validator.isEmail(email)) {
      return res.status(400).send('Email inválido')
    }

    if (!senha || senha.length < 6) {
      return res.status(400).send('Senha deve ter no mínimo 6 caracteres')
    }

    // 🔎 VERIFICA SE JÁ EXISTE
    const existing = await pool.query(
      'SELECT id FROM usuarios WHERE email = $1',
      [email]
    )

    if (existing.rows.length > 0) {
      return res.status(400).send('Usuário já existe')
    }

    // 🔐 HASH DA SENHA
    const hash = await bcrypt.hash(senha, 10)

    // 💾 SALVA
    await pool.query(
      'INSERT INTO usuarios (email, senha) VALUES ($1, $2)',
      [email, hash]
    )

    res.send('Usuário criado com sucesso')

  } catch (err) {
    console.error(err)

    // ❌ NÃO EXPOR ERRO REAL EM PRODUÇÃO
    res.status(500).send('Erro interno do servidor')
  }
})



app.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, senha } = req.body

    // 🔒 VALIDAÇÃO (COLOCA AQUI 👇)
    if (!email || !validator.isEmail(email)) {
      return res.status(400).send('Email inválido')
    }

    if (!senha || senha.length < 6) {
      return res.status(400).send('Senha muito curta')
    }

    // 🔎 BUSCA USUÁRIO
    const result = await pool.query(
      'SELECT * FROM usuarios WHERE email = $1',
      [email]
    )

    const user = result.rows[0]

    if (!user || !(await bcrypt.compare(senha, user.senha))) {
  return res.status(401).send('Credenciais inválidas')
}

    // 🎟️ GERA TOKEN
    const token = jwt.sign(
      { id: user.id, email: user.email },
      SECRET,
      { expiresIn: '2h' }
    )

    res.json({ token })

  } catch (err) {
    console.error(err)
    res.status(500).send('Erro interno do servidor')
  }
})


app.post("/whatsapp/:tipo/:id",verificarToken, async (req, res) => {
  const { tipo, id } = req.params;

  try {
    const result = await pool.query(
      "SELECT * FROM alunos WHERE id = $1",
      [id]
    );

    const aluno = result.rows[0];

    if (!aluno) {
      return res.status(404).send("Aluno não encontrado");
    }

    let mensagem = "";

    // 🎯 PERSONALIZAÇÃO
    switch (tipo) {
      case "cobranca":
        mensagem = `Olá ${aluno.nome}, sua mensalidade está pendente 💳. Qualquer dúvida estou à disposição!`;
        break;

      case "vencimento":
        mensagem = `Olá ${aluno.nome}, sua mensalidade vence em breve 📅. Não esqueça de realizar o pagamento 😉`;
        break;

      case "agendamento":
        mensagem = `Olá ${aluno.nome}, vamos agendar sua próxima aula? 📚 Me diz um horário disponível pra você!`;
        break;

      case "relatorio":
        mensagem = `Olá ${aluno.nome}, segue um resumo do seu desempenho 📊. Qualquer dúvida estou à disposição!`;
        break;

      default:
        return res.status(400).send("Tipo inválido");
    }

    await axios.post(
      "https://graph.facebook.com/v19.0/1114807448375607/messages",
      {
        messaging_product: "whatsapp",
        to: aluno.telefone,
        type: "text",
        text: {
          body: mensagem,
        },
      },
      {
        headers: {
          Authorization: `Bearer ${process.env.WPP_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    res.send("Mensagem enviada 🚀");
  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).send("Erro ao enviar mensagem");
  }
});


app.post("/whatsapp/disparo",verificarToken, upload.single("arquivo"), async (req, res) => {
  try {
    const numeros = JSON.parse(req.body.numeros);
    const mensagem = req.body.mensagem;

    // 🔥 UPLOAD (UMA VEZ SÓ)
    let mediaUrl = null;
    let mediaType = null;

    if (req.file) {
      const result = await cloudinary.uploader.upload(req.file.path, {
        resource_type: "auto",
      });

      mediaUrl = result.secure_url;

      // 🔥 detecta tipo automaticamente
      if (result.resource_type === "video") {
        mediaType = "video";
      } else {
        mediaType = "image";
      }

      console.log("URL DA MÍDIA:", mediaUrl);
    }

    // 🔥 LOOP DE ENVIO
   for (const numero of numeros) {

  let payload;

  if (mediaUrl) {
    if (mediaType === "video") {
      payload = {
        messaging_product: "whatsapp",
        to: numero,
        type: "video",
        video: {
          link: mediaUrl,
          caption: mensagem
        }
      };
    } else {
      payload = {
        messaging_product: "whatsapp",
        to: numero,
        type: "image",
        image: {
          link: mediaUrl,
          caption: mensagem
        }
      };
    }
  } else {
    payload = {
      messaging_product: "whatsapp",
      to: numero,
      type: "text",
      text: {
        body: mensagem
      }
    };
  }

  try {
    await axios.post(
      "https://graph.facebook.com/v19.0/1114807448375607/messages",
      payload,
      {
        headers: {
          Authorization: `Bearer ${process.env.WPP_TOKEN}`,
          "Content-Type": "application/json",
        },
      }
    );

    // ✅ LOG SUCESSO
    await pool.query(
      "INSERT INTO logs_envio (numero, mensagem, status) VALUES ($1, $2, $3)",
      [numero, mensagem, "enviado"]
    );

  } catch (err) {
    console.error("ERRO ENVIO:", err.response?.data || err);

    // ❌ LOG ERRO
    await pool.query(
      "INSERT INTO logs_envio (numero, mensagem, status, erro) VALUES ($1, $2, $3, $4)",
      [numero, mensagem, "erro", JSON.stringify(err.response?.data || err.message)]
    );
  }

  await new Promise(r => setTimeout(r, 1200));
}

    res.send("Disparo finalizado 🚀");

  } catch (err) {
    console.error(err.response?.data || err);
    res.status(500).send("Erro no disparo");
  }
});

app.get("/logs", verificarToken, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM logs_envio ORDER BY id DESC LIMIT 100"
    );

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro ao buscar logs");
  }
});



// 🚀 INICIAR SERVIDOR
const PORT = process.env.PORT || 3000

app.listen(PORT, () => {
  console.log('Servidor rodando')
})