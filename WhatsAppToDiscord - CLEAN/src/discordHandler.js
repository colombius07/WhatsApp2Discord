// discordHandler.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
require('dotenv').config();


const { Client, Intents, MessageButton, MessageActionRow } = require('discord.js');

const state = require('./state.js');
const utils = require('./utils.js');

const env = process.env.APP_ENV;
const credentialsFilePath = process.env.credentialsFilePath;
let failedAttempts = 0;
const failedAttempt = process.env.MAX_FAILED_ATTEMPTS;
const lockout = process.env.LOCKOUT_DURATION * 1000;  
const passwordLength = process.env.MIN_PASSWORD_LENGTH;
const LOCKOUT_MESSAGE = 'Trop de tentatives échouées. Le déchiffrement est verrouillé.';

const saltRounds = 10;

const client = new Client({
  intents: [
    Intents.FLAGS.GUILDS,
    Intents.FLAGS.GUILD_MESSAGES,
    Intents.FLAGS.GUILD_MESSAGE_REACTIONS,
    Intents.FLAGS.MESSAGE_CONTENT,
  ],
});
let controlChannel;

const setControlChannel = async () => {
  controlChannel = await client.channels.fetch(state.settings.ControlChannelID).catch(() => null);
};

client.on('ready', async () => {
  await setControlChannel();
});

client.on('error', (error) => {
  console.error('Discord client error:', error);
});

client.on('channelDelete', async (channel) => {
  const jid = utils.discord.channelIdToJid(channel.id);
  delete state.chats[jid];
  delete state.goccRuns[jid];
  state.settings.Categories = state.settings.Categories.filter((id) => channel.id !== id);
});

client.on('whatsappMessage', async (message) => {
  if ((state.settings.oneWay >> 0 & 1) === 0) {
    return;
  }
  
  let msgContent = '';
  const files = [];
  const webhook = await utils.discord.getOrCreateChannel(message.channelJid);

  if (message.isGroup && state.settings.WAGroupPrefix) { msgContent += `[${message.name}] `; }

  if (message.isForwarded) {
    msgContent += `forwarded message:\n${message.content.split('\n').join('\n> ')}`;
  }
  else if (message.quote) {
    msgContent += `> ${message.quote.name}: ${message.quote.content.split('\n').join('\n> ')}\n${message.content}`;
  }
  else if (message.isEdit) {
    msgContent += "Edited message:\n" + message.content;
  }
  else {
    msgContent += message.content;
  }

  if (message.file) {
    if (message.file.largeFile && state.settings.LocalDownloads) {
      msgContent += await utils.discord.downloadLargeFile(message.file);
    }
    else if (message.file === -1 && !state.settings.LocalDownloads) {
      msgContent += "WA2DC Attention: Received a file, but it's over 8MB. Check WhatsApp on your phone or enable local downloads.";
    } else {
      files.push(message.file);
    }
  }

  if (msgContent || files.length) {
    msgContent = utils.discord.partitionText(msgContent);
    while (msgContent.length > 1) {
      // eslint-disable-next-line no-await-in-loop
      await utils.discord.safeWebhookSend(webhook, {
        content: msgContent.shift(),
        username: message.name,
        avatarURL: message.profilePic,
      }, message.channelJid);
    }
    const dcMessage = await utils.discord.safeWebhookSend(webhook, {
      content: msgContent.shift() || null,
      username: message.name,
      files,
      avatarURL: message.profilePic,
    }, message.channelJid);
    if (dcMessage.channel.type === 'GUILD_NEWS' && state.settings.Publish) {
      await dcMessage.crosspost();
    }

    if (message.id != null)
      state.lastMessages[dcMessage.id] = message.id;
  }
});

client.on('whatsappReaction', async (reaction) => {
  if ((state.settings.oneWay >> 0 & 1) === 0) {
    return;
  }

  const channelId = state.chats[reaction.jid]?.channelId;
  const messageId = state.lastMessages[reaction.id];
  if (channelId == null || messageId == null) { return; }

  const channel = await utils.discord.getChannel(channelId);
  const message = await channel.messages.fetch(messageId);
  await message.react(reaction.text).catch(async err => {
    if (err.code === 10014) {
      await channel.send(`Unknown emoji reaction (${reaction.text}) received. Check WhatsApp app to see it.`);
    }
  });
});

client.on('whatsappCall', async ({ call, jid }) => {
  if ((state.settings.oneWay >> 0 & 1) === 0) {
    return;
  }
  
  const webhook = await utils.discord.getOrCreateChannel(jid);

  const name = utils.whatsapp.jidToName(jid);
  const callType = call.isVideo ? 'video' : 'voice';
  let content = '';

  switch (call.status) {
    case 'offer':
      content = `${name} is ${callType} calling you! Check your phone to respond.`
      break;
    case 'timeout':
      content = `Missed a ${callType} call from ${name}!`
      break;
  }

  if (content !== '') {
    await webhook.send({
      content,
      username: name,
      avatarURL: await utils.whatsapp.getProfilePic(call),
    });
  }
});

const commands = {
  async ping(message) {
    controlChannel.send(`Pong ${Date.now() - message.createdTimestamp}ms!`);
  },
  async pairwithcode(_message, params) {
    if (params.length !== 1) {
      await controlChannel.send('Please enter your number. Usage: `pairWithCode <number>`. Don\'t use "+" or any other special characters.');
      return;
    }

    const code = await state.waClient.requestPairingCode(params[0]);
    await controlChannel.send(`Your pairing code is: ${code}`);
  },
  async start(_message, params) {
    if (!params.length) {
      await controlChannel.send('Please enter a phone number or name. Usage: `start <number with country code or name>`.');
      return;
    }

    // eslint-disable-next-line no-restricted-globals
    const jid = utils.whatsapp.toJid(params.join(' '));
    if (!jid) {
      await controlChannel.send(`Couldn't find \`${params.join(' ')}\`.`);
      return;
    }
    await utils.discord.getOrCreateChannel(jid);

    if (state.settings.Whitelist.length) {
      state.settings.Whitelist.push(jid);
    }
  },
  async list(_message, params) {
    let contacts = utils.whatsapp.contacts();
    if (params) { contacts = contacts.filter((name) => name.toLowerCase().includes(params.join(' '))); }
    const message = utils.discord.partitionText(
      contacts.length
        ? `${contacts.join('\n')}\n\nNot the whole list? You can refresh your contacts by typing \`resync\``
        : 'No results were found.',
    );
    while (message.length !== 0) {
      // eslint-disable-next-line no-await-in-loop
      await controlChannel.send(message.shift());
    }
  },
  async addtowhitelist(message, params) {
    const channelID = /<#(\d*)>/.exec(message)?.[1];
    if (params.length !== 1 || !channelID) {
      await controlChannel.send('Please enter a valid channel name. Usage: `addToWhitelist #<target channel>`.');
      return;
    }

    const jid = utils.discord.channelIdToJid(channelID);
    if (!jid) {
      await controlChannel.send("Couldn't find a chat with the given channel.");
      return;
    }

    state.settings.Whitelist.push(jid);
    await controlChannel.send('Added to the whitelist!');
  },
  async removefromwhitelist(message, params) {
    const channelID = /<#(\d*)>/.exec(message)?.[1];
    if (params.length !== 1 || !channelID) {
      await controlChannel.send('Please enter a valid channel name. Usage: `removeFromWhitelist #<target channel>`.');
      return;
    }

    const jid = utils.discord.channelIdToJid(channelID);
    if (!jid) {
      await controlChannel.send("Couldn't find a chat with the given channel.");
      return;
    }

    state.settings.Whitelist = state.settings.Whitelist.filter((el) => el !== jid);
    await controlChannel.send('Removed from the whitelist!');
  },
  async listwhitelist() {
    await controlChannel.send(
      state.settings.Whitelist.length
        ? `\`\`\`${state.settings.Whitelist.map((jid) => utils.whatsapp.jidToName(jid)).join('\n')}\`\`\``
        : 'Whitelist is empty/inactive.',
    );
  },
  async setdcprefix(message, params) {
    if (params.length !== 0) {
      const prefix = message.content.split(' ').slice(1).join(' ');
      state.settings.DiscordPrefixText = prefix;
      await controlChannel.send(`Discord prefix is set to ${prefix}!`);
    } else {
      state.settings.DiscordPrefixText = null;
      await controlChannel.send('Discord prefix is set to your discord username!');
    }
  },
  async enabledcprefix() {
    state.settings.DiscordPrefix = true;
    await controlChannel.send('Discord username prefix enabled!');
  },
  async disabledcprefix() {
    state.settings.DiscordPrefix = false;
    await controlChannel.send('Discord username prefix disabled!');
  },
  async enablewaprefix() {
    state.settings.WAGroupPrefix = true;
    await controlChannel.send('WhatsApp name prefix enabled!');
  },
  async disablewaprefix() {
    state.settings.WAGroupPrefix = false;
    await controlChannel.send('WhatsApp name prefix disabled!');
  },
  async enablewaupload() {
    state.settings.UploadAttachments = true;
    await controlChannel.send('Enabled uploading files to WhatsApp!');
  },
  async disablewaupload() {
    state.settings.UploadAttachments = false;
    await controlChannel.send('Disabled uploading files to WhatsApp!');
  },
  async help() {
    await controlChannel.send('See all the available commands at https://fklc.github.io/WhatsAppToDiscord/#/commands\nDe plus, Voici la commande d\'archivage : `archive <nom-du-salon> <nom de l\'archive>`\nLe chiffrage se fait sous cette forme : `encrypt <nom-du-fichier> <mot-de-passe>`\nLe déchiffrage se fait sous cette forme : `decrypt <nom-du-fichier> <mot-de-passe>`');
  },
  async resync() {
    await state.waClient.authState.keys.set({
      'app-state-sync-version': { critical_unblock_low: null },
    });
    await state.waClient.resyncAppState(['critical_unblock_low']);
    for (const [jid, attributes] of Object.entries(await state.waClient.groupFetchAllParticipating())) { state.waClient.contacts[jid] = attributes.subject; }
    await utils.discord.renameChannels();
    await controlChannel.send('Re-synced!');
  },
  async enablelocaldownloads() {
    state.settings.LocalDownloads = true;
    await controlChannel.send(`Enabled local downloads. You can now download files larger than 8MB.`);
  },
  async disablelocaldownloads() {
    state.settings.LocalDownloads = false;
    await controlChannel.send(`Disabled local downloads. You won't be able to download files larger than 8MB.`);
  },
  async getdownloadmessage() {
    await controlChannel.send(`Download message format is set to "${state.settings.LocalDownloadMessage}"`);
  },
  async setdownloadmessage(message) {
    state.settings.LocalDownloadMessage = message.content.split(' ').slice(1).join(' ');
    await controlChannel.send(`Set download message format to "${state.settings.LocalDownloadMessage}"`);
  },
  async getdownloaddir() {
    await controlChannel.send(`Download path is set to "${state.settings.DownloadDir}"`);
  },
  async setdownloaddir(message) {
    state.settings.DownloadDir = message.content.split(' ').slice(1).join(' ');
    await controlChannel.send(`Set download path to "${state.settings.DownloadDir}"`);
  },
  async enablepublishing() {
    state.settings.Publish = true;
    await controlChannel.send(`Enabled publishing messages sent to news channels.`);
  },
  async disablepublishing() {
    state.settings.Publish = false;
    await controlChannel.send(`Disabled publishing messages sent to news channels.`);
  },
  async enablechangenotifications() {
    state.settings.ChangeNotifications = true;
    await controlChannel.send(`Enabled profile picture change and status update notifications.`);
  },
  async disablechangenotifications() {
    state.settings.ChangeNotifications = false;
    await controlChannel.send(`Disabled profile picture change and status update notifications.`);
  },
  async autosaveinterval(_message, params) {
    if (params.length !== 1) {
      await controlChannel.send("Usage: autoSaveInterval <seconds>\nExample: autoSaveInterval 60");
      return;
    }
    state.settings.autoSaveInterval = +params[0];
    await controlChannel.send(`Changed auto save interval to ${params[0]}.`);
  },
  async lastmessagestorage(_message, params) {
    if (params.length !== 1) {
      await controlChannel.send("Usage: lastMessageStorage <size>\nExample: lastMessageStorage 1000");
      return;
    }
    state.settings.lastMessageStorage = +params[0];
    await controlChannel.send(`Changed last message storage size to ${params[0]}.`);
  },
  async oneway(_message, params) {
    if (params.length !== 1) {
      await controlChannel.send("Usage: oneWay <discord|whatsapp|disabled>\nExample: oneWay whatsapp");
      return;
    }
    
    if (params[0] === "disabled") {
      state.settings.oneWay = 0b11;
      await controlChannel.send(`Two way communication is enabled.`);
    } else if (params[0] === "whatsapp") {
      state.settings.oneWay = 0b10;
      await controlChannel.send(`Messages will be only sent to WhatsApp.`);
    } else if (params[0] === "discord") {
      state.settings.oneWay = 0b01;
      await controlChannel.send(`Messages will be only sent to Discord.`);
    } else {
      await controlChannel.send("Usage: oneWay <discord|whatsapp|disabled>\nExample: oneWay whatsapp");
    }
  },
  async archive(message, args) {
    		// Vérifier si l'utilisateur a spécifié le salon et le nom du fichier
		if (args.length < 2) {
			return message.reply('Veuillez spécifier le salon et le nom du fichier.');
		}
	
		const targetChannelName = args[0];
		const fileName = args.slice(1).join('_'); 
	
		// Récupérer le salon cible
		const targetChannel = message.guild.channels.cache.find(channel => channel.name === targetChannelName);
	
		if (!targetChannel) {
			return message.reply(`Le salon ${targetChannelName} n'a pas été trouvé.`);
		}
	
		// Appeler la fonction d'archive
		await archiveChannel(message, targetChannel, fileName);
  },
  async encrypt(message, args) {
    try {
      if (failedAttempts > failedAttempt) {

        console.error('Trop de tentatives échouées. Le chiffrement est verrouillé.');

        return LOCKOUT_MESSAGE;
      }
  
      if (args.length < 2) {
        return message.reply('Veuillez spécifier le chemin du fichier à chiffrer et le mot de passe.');
      }
  
      const fileName = args[0];
      const filePath = path.join('archives', `${fileName}.txt`);
      const password = args[1];
  
      if (password.length < 8) {
        message.reply(`Le mot de passe doit être supérieur à ${passwordLength} caractères.`);
      } else {
        await encryptFile(filePath, password);
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        // Sauvegarder les informations dans le fichier temporaire
        saveCredentials(fileName, hashedPassword);
  
        message.channel.send(`Le fichier a été chiffré avec succès et le fichier d'origine a été supprimé.`);
  
        // Remettre à zéro le compteur de tentatives infructueuses en cas de succès
        failedAttempts = 0;

        message.delete();
      }
    } catch (error) {

      console.error('Erreur lors du chiffrement du fichier :', error);

      // Incrémenter le compteur de tentatives infructueuses en cas d'erreur
      failedAttempts++;
      throw error;
    }
  },
  async decrypt(message, args) {
    if(env === 'dev'){
      console.log("nombre max d'essaie :",failedAttempt);
      console.log("nombre d'essaie actuel :",failedAttempts);
    }
    try {
      if (failedAttempts >= failedAttempt) {

        console.error('Trop de tentatives échouées. Le déchiffrement est verrouillé.');

        return LOCKOUT_MESSAGE;
      }
  
      if (args.length < 2) {
        return message.reply('Veuillez spécifier le chemin du fichier à déchiffrer et le mot de passe.');
      }
  
      const fileName = args[0];
      const filePath = path.join('archives', `${fileName}_encrypted.txt`);
      const password = args[1];
  
      // Récupérer le mot de passe haché depuis le fichier de credentials
      const hashedPasswordFromCredentials = getHashedPasswordFromCredentials(fileName);
      if (hashedPasswordFromCredentials === null) {
        // Gérer le cas où le mot de passe haché n'est pas trouvé

        console.error('Mot de passe haché non trouvé pour le fichier spécifié.');

        return 'Erreur lors de la récupération du mot de passe haché. Veuillez réessayer.';
      }
  
      // Vérifier le mot de passe en utilisant bcrypt.compare
      const passwordMatch = await bcrypt.compare(password, hashedPasswordFromCredentials);
  
      if (!passwordMatch) {

        console.error('Tentative de déchiffrement avec un mot de passe invalide.');

        failedAttempts++;
        if (failedAttempts >= failedAttempt) {
          setTimeout(unlockTimer, lockout);  // Lancer le timer de réinitialisation du verrouillage
        }
        return 'Mot de passe invalide. Trop de tentatives échouées. Le déchiffrement est verrouillé.';
      }
  
      await decryptFile(filePath, password);

      // Supprimer le fichier chiffré après le déchiffrement réussi
      fs.unlinkSync(filePath);

      message.reply(`Le fichier a été déchiffré avec succès.`);
  
      // Remettre à zéro le compteur de tentatives infructueuses en cas de succès
      failedAttempts = 0;
    } catch (error) {

      console.error('Erreur lors du déchiffrement du fichier :', error);

      failedAttempts++;
      if (failedAttempts >= failedAttempt) {
        setTimeout(unlockTimer, lockout);  // Lancer le timer de réinitialisation du verrouillage
      }
      throw error;
    }
  },
  	// Supprime des messages
	async clear(message, args){
		const amount = parseInt(args[0]) || 1;

		if (isNaN(amount) || amount < 1 || amount > 100) {
			return message.channel.send('Veuillez spécifier un nombre entre 1 et 100.');
		}

		await message.channel.bulkDelete(amount, true).catch(error => {
			console.error(error);
			message.reply('Une erreur s\'est produite lors de la suppression des messages.');
		});
	},
  async embed(message, params) {
    if (params.length < 2) {
        await message.channel.send('Usage: `embed <title> <description>`');
        return;
    }

    let title = '';
    let description = '';

    if (params[0].startsWith('"')) {
        for (let i = 0; i < params.length; i++) {
            title += params[i] + ' ';
            if (params[i].endsWith('"')) {
                title = title.substring(1, title.length - 1);
                description = params.slice(i + 1).join(' ');
                break;
            }
        }
    } else {
        title = params[0];
        description = params.slice(1).join(' ');
    }
    
    const targetChannel = message.guild.channels.cache.find(channel => channel.name === title);

    const embed = {
        color: 0x0099ff,
        title: title,
        description: description,
        timestamp: new Date(),
    };
    const row = new MessageActionRow()
      .addComponents(
        new MessageButton()
          .setCustomId('archiveButton')
          .setLabel('Archive')
          .setStyle('PRIMARY')
          .setEmoji('📁')
      );


    if(targetChannel)
    await controlChannel.send({ embeds: [embed], components: [row] });
    else
    await controlChannel.send({ embeds: [embed]});
    // Mettre en place un collecteur pour attendre les interactions de boutons
    const filter = (interaction) => interaction.customId === 'archiveButton';
    const collector = controlChannel.createMessageComponentCollector({ filter, time: 15000 });



    collector.on('collect', async (interaction) => {
        // Si le bouton d'archive est cliqué, exécutez la commande d'archivage

	
        if (!targetChannel) {
          return message.reply(`Le salon ${title} n'a pas été trouvé.`);
        }
        await archiveChannel(message, targetChannel, title);
        collector.stop();
    });

    collector.on('end', () => {
        row.components.forEach(button => button.setDisabled(true));
        controlChannel.send({ components: [row] });
    });
}
,
  async unknownCommand(message) {
    await controlChannel.send(`Unknown command: \`${message.content}\`\nType \`help\` to see available commands`);
  },
};

const generateUniqueFileName = (fileName, suffix = 1) => {
  const baseFileName = suffix > 1 ? `${fileName}(${suffix})` : fileName;

  if (fs.existsSync(`${baseFileName}.txt`)) {
      return generateUniqueFileName(fileName, suffix + 1);
  }

  return `${baseFileName}.txt`;
};
const archiveChannel = async (message, targetChannel, fileName) => {
  if (!targetChannel) {
      message.reply(`Le salon ${targetChannelName} n'a pas été trouvé. (archive channel)`);
      return;
  }

  // Copier tous les messages du salon cible dans le fichier texte
  await copyAllMessages(targetChannel, fileName);

  /* SUPPRESSION DU SALON
  // Supprimer le salon
  try {
      await targetChannel.delete();
      if(env === 'dev){
        console.log(`Le salon ${targetChannel.name} a été supprimé avec succès.`);
      }
  } catch (error) {

      console.error('Erreur lors de la suppression du salon :', error);

      throw new Error('Une erreur s\'est produite lors de la suppression du salon.');
  }
*/

  message.reply(`Tous les messages ont été archivés avec succès dans ${fileName} et le salon a été supprimé.`);
};
const copyAllMessages = async (targetChannel, fileName) => {
  let allMessages = [];
  let lastMessageId = null;
  let messagesFetched = true;

  while (messagesFetched) {
    const messages = await targetChannel.messages.fetch({ limit: 100, before: lastMessageId });

    if (messages.size > 0) {
      // Ajouter les messages au tableau
      allMessages.push(...messages.values());

      // Mettre à jour l'ID du dernier message récupéré
      lastMessageId = messages.last().id;
    } else {
      // Aucun message supplémentaire à récupérer
      messagesFetched = false;
    }
  }

  // Retirer le dernier message du tableau allMessages
  allMessages.shift();

  // Traiter les messages et les sauvegarder dans un fichier
  const messageContents = allMessages.map(msg => `${msg.author.tag} (${formatDate(msg.createdAt)}): ${msg.content}`);
  messageContents.reverse();

  const uniqueFileName = generateUniqueFileName(path.join('archives', fileName));
  const contentToWrite = messageContents.join('\n');

  fs.writeFile(uniqueFileName, contentToWrite, 'utf8', (err) => {
    if (err) {

      console.error('Erreur lors de l\'écriture dans le fichier :', err);

      throw new Error('Une erreur s\'est produite lors de la copie des messages.');
    }

    if(env === 'dev'){
      console.log(`Tous les messages ont été copiés avec succès dans ${uniqueFileName}`);
    }
  });
};
const formatDate = (date) => {
  const options = { year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' };
  return new Intl.DateTimeFormat('fr-FR', options).format(date);
};
const generateKey = (password, salt) => {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
};
const encryptFile = async (filePath, password) => {
  try {
    if (!validatePassword(password)) {

      console.error('Tentative de chiffrement avec un mot de passe invalide.');

      return 'Mot de passe invalide. Veuillez choisir un mot de passe d\'au moins 8 caractères.';
    }

    const input = fs.readFileSync(filePath, 'utf8');
    const salt = crypto.randomBytes(16);
    const key = await generateKey(password, salt);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    const encryptedContent = Buffer.concat([cipher.update(input, 'utf8'), cipher.final()]);

    const encryptedWithSaltAndIv = Buffer.concat([salt, iv, encryptedContent]);

    const encryptedFileName = filePath.replace('.txt', '_encrypted.txt');
    fs.writeFileSync(encryptedFileName, encryptedWithSaltAndIv);

    // Supprimer le fichier en clair après chiffrement
    fs.unlinkSync(filePath);
    if(env === 'dev'){
      console.log(`Le fichier a été chiffré avec succès. Contenu chiffré sauvegardé dans ${encryptedFileName}.`);
    }
    // Remettre à zéro le compteur de tentatives infructueuses en cas de succès
    failedAttempts = 0;

    return encryptedFileName;
  } catch (error) {

      console.error('Erreur lors du chiffrement du fichier :', error);

    throw error;
  }
};
const decryptFile = (filePath, password) => {
  try {
    const encryptedData = fs.readFileSync(filePath);
    const salt = encryptedData.subarray(0, 16);
    const iv = encryptedData.subarray(16, 32);
    const encryptedContent = encryptedData.subarray(32);

    const key = generateKey(password, salt);

    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    const decryptedContent = Buffer.concat([decipher.update(encryptedContent), decipher.final()]);

    const decryptedFileName = filePath.replace('_encrypted.txt', '.txt');
    fs.writeFileSync(decryptedFileName, decryptedContent, 'utf8');
    if(env === 'dev'){
      console.log(`Le fichier a été déchiffré avec succès. Contenu déchiffré sauvegardé dans ${decryptedFileName}.`);
    }
    // Supprimer le credential correspondant
    removeCredentialFromJSON(filePath);

    return decryptedFileName;
  } catch (error) {

      console.error('Erreur lors du déchiffrement du fichier :', error);

    failedAttempts++;
    if (failedAttempts >= failedAttempt) {
      setTimeout(unlockTimer, lockout);  // Lancer le timer de réinitialisation du verrouillage
    }
    throw error;
  }
};
const removeCredentialFromJSON = (filePath) => {
  try {
    let credentials = {};

    // Vérifier si le fichier JSON existe
    if (fs.existsSync(credentialsFilePath)) {
      // Lire le fichier JSON existant s'il n'est pas vide
      const fileContent = fs.readFileSync(credentialsFilePath, 'utf8');
      if (fileContent.trim() !== '') {
        credentials = JSON.parse(fileContent);
      }

      // Extraire le nom du fichier sans l'extension et le chemin
      const fileName = path.basename(filePath, path.extname(filePath));

      // Retirer "_encrypted" du nom de fichier
      const fileNameWithoutExtension = fileName.replace('_encrypted', '');

      // Supprimer l'entrée correspondante
      delete credentials[fileNameWithoutExtension];

      // Sauvegarder les informations mises à jour dans le fichier JSON
      fs.writeFileSync(credentialsFilePath, JSON.stringify(credentials, null, 2), 'utf8');
      if(env === 'dev'){
        console.log(`Credential correspondant à ${fileNameWithoutExtension} supprimé du fichier JSON.`);
      }
    }
  } catch (error) {

      console.error('Erreur lors de la suppression du credential du fichier JSON :', error);

    throw error;
  }
};
const validatePassword = (password) => {
  return password.length >= passwordLength;
};
const unlockTimer = () => {
  if(env === 'dev'){
    console.log('Réinitialisation du verrouillage.');
  }
  failedAttempts = 0;  // Réinitialiser le compteur après la durée du verrouillage
};
const saveCredentials = (fileName, password) => {
  try {
    let credentials = {};

    // Vérifier si le fichier JSON existe
    if (fs.existsSync(credentialsFilePath)) {
      // Lire le fichier JSON existant s'il n'est pas vide
      const fileContent = fs.readFileSync(credentialsFilePath, 'utf8');
      if (fileContent.trim() !== '') {
        credentials = JSON.parse(fileContent);
      }
    }

    // Ajouter les nouvelles informations
    credentials[fileName] = password;

    // Sauvegarder les informations mises à jour dans le fichier JSON
    fs.writeFileSync(credentialsFilePath, JSON.stringify(credentials, null, 2), 'utf8');
    if(env === 'dev'){
    console.log('Informations d\'identification sauvegardées avec succès.');
    }
  } catch (error) {

    console.error('Erreur lors de la sauvegarde des informations d\'identification :', error);

    throw error;
  }
};
const getHashedPasswordFromCredentials = (fileName) => {
  const credentialsFilePath = process.env.credentialsFilePath;

  try {
    let credentials = {};

    // Vérifier si le fichier JSON existe
    if (fs.existsSync(credentialsFilePath)) {
      // Lire le fichier JSON existant s'il n'est pas vide
      const fileContent = fs.readFileSync(credentialsFilePath, 'utf8');
      if (fileContent.trim() !== '') {
        credentials = JSON.parse(fileContent);
      }

      // Récupérer le mot de passe haché correspondant au fichier
      return credentials[fileName];
    }

    return null; // Retourner null si le fichier JSON de credentials n'existe pas
  } catch (error) {
    console.error('Erreur lors de la récupération du mot de passe haché depuis les credentials :', error);

    throw error;
  }
};


client.on('messageCreate', async (message) => {
  if (message.author === client.user || message.webhookId != null) {
    return;
  }

  if (message.channel === controlChannel) {
    const command = message.content.toLowerCase().split(' ');
    await (commands[command[0]] || commands.unknownCommand)(message, command.slice(1));
  } else {
    const jid = utils.discord.channelIdToJid(message.channel.id);
    if (jid == null) {
      return;
    }

    state.waClient.ev.emit('discordMessage', { jid, message });
  }
});

client.on('messageUpdate', async (_, message) => {
  if (message.webhookId != null) {
    return;
  }

  const jid = utils.discord.channelIdToJid(message.channelId);
  if (jid == null) {
    return;
  }

  const messageId = state.lastMessages[message.id];
  if (messageId == null) {
    await message.channel.send("Couldn't edit the message. You can only edit the last 500 messages.");
    return;
  }

  state.waClient.ev.emit('discordEdit', { jid, message });
})

client.on('messageReactionAdd', async (reaction, user) => {
  const jid = utils.discord.channelIdToJid(reaction.message.channel.id);
  if (jid == null) {
    return;
  }
  const messageId = state.lastMessages[reaction.message.id];
  if (messageId == null) {
    await reaction.message.channel.send("Couldn't send the reaction. You can only react to last 500 messages.");
    return;
  }
  if (user.id === state.dcClient.user.id) {
    return;
  }

  state.waClient.ev.emit('discordReaction', { jid, reaction, removed: false });
});

client.on('messageReactionRemove', async (reaction, user) => {
  const jid = utils.discord.channelIdToJid(reaction.message.channel.id);
  if (jid == null) {
    return;
  }
  const messageId = state.lastMessages[reaction.message.id];
  if (messageId == null) {
    await reaction.message.channel.send("Couldn't remove the reaction. You can only react to last 500 messages.");
    return;
  }
  if (user.id === state.dcClient.user.id) {
    return;
  }

  state.waClient.ev.emit('discordReaction', { jid, reaction, removed: true });
});

module.exports = {
  start: async () => {
    await client.login(state.settings.Token);
    return client;
  },
  setControlChannel,
};
