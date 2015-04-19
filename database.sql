CREATE TABLE IF NOT EXISTS `pages` (
      `id` int(11) NOT NULL,
      `keyhash` varchar(128) NOT NULL,
      `passhash` varchar(128) NOT NULL,
      `contenthash` varchar(128) NOT NULL,
      `content` text NOT NULL,
      `accessed` datetime NOT NULL,
      `modified` datetime NOT NULL
    ) ENGINE=MyISAM AUTO_INCREMENT=1 DEFAULT CHARSET=utf8;

ALTER TABLE `pages`
  ADD PRIMARY KEY (`id`), ADD UNIQUE KEY `keyhash` (`keyhash`), ADD KEY `passhash` (`passhash`);

ALTER TABLE `pages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT,AUTO_INCREMENT=1;
