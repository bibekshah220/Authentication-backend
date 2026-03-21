import { createTransport } from "nodemailer";

export const sendEmail = async (email, subject, html) => {

const transporter = createTransport({
    host: "smtp.gmail.com",
    port: 465,
    auth: {
        user:"abcdxyz",
        pass:"abcdxyz"
    },
})

await transporter.sendMail({
    from: "abcdxyz",
    to: email,
    subject: subject,
    html: html,
})
}

export default sendEmail;