import { createTransport } from "nodemailer";

export const sendEmail = async (email, subject, html) => {

const transporter = createTransport({
    host: "smtp.gmail.com",
    port: 465,
    auth: {
        user:process.env.SMPT_USER,
        pass:process.env.SMPT_PASSWORD
    },
})

await transporter.sendMail({
    from: process.env.SMPT_USER,
    to: email,
    subject: subject,
    html: html,
})
}

export default sendEmail;