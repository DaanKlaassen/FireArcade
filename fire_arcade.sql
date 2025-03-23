-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 23, 2025 at 11:54 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `fire_arcade`
--

-- --------------------------------------------------------

--
-- Table structure for table `contract`
--

CREATE TABLE `contract` (
  `id` int(11) NOT NULL,
  `gebruiker_id` int(11) DEFAULT NULL,
  `contract_begin_datum` datetime NOT NULL,
  `contract_eind_datum` datetime NOT NULL,
  `contract_status` varchar(50) NOT NULL,
  `contract_termen` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `gebruiker`
--

CREATE TABLE `gebruiker` (
  `id` int(11) NOT NULL,
  `naam` varchar(255) NOT NULL,
  `emailadres` varchar(255) NOT NULL,
  `telefoonnummer` varchar(20) DEFAULT NULL,
  `wachtwoord_hash` varchar(255) NOT NULL,
  `rol` varchar(50) NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `Verwijderd` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `gebruiker`
--

INSERT INTO `gebruiker` (`id`, `naam`, `emailadres`, `telefoonnummer`, `wachtwoord_hash`, `rol`, `created_at`, `updated_at`, `Verwijderd`) VALUES
(1, 'Gie leurs', 'gieleurs@gmail.com', '0612345678', 'test', 'klant', '2025-03-23 21:33:37', '2025-03-23 21:33:37', 0);

-- --------------------------------------------------------

--
-- Table structure for table `machine`
--

CREATE TABLE `machine` (
  `id` int(11) NOT NULL,
  `game_naam` varchar(255) NOT NULL,
  `publicatiedatum` datetime NOT NULL,
  `fabrikant` varchar(255) NOT NULL,
  `voorraad` int(11) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `ticket`
--

CREATE TABLE `ticket` (
  `id` int(11) NOT NULL,
  `gebruiker_id` int(11) DEFAULT NULL,
  `titel` varchar(255) NOT NULL,
  `toegewezen` varchar(255) DEFAULT NULL,
  `beschrijving` text DEFAULT NULL,
  `status` varchar(50) NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `updated_at` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `verkocht`
--

CREATE TABLE `verkocht` (
  `id` int(11) NOT NULL,
  `machine_id` int(11) DEFAULT NULL,
  `gebruiker_id` int(11) DEFAULT NULL,
  `game_naam` varchar(255) NOT NULL,
  `verkoopdatum` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `contract`
--
ALTER TABLE `contract`
  ADD PRIMARY KEY (`id`),
  ADD KEY `gebruiker_id` (`gebruiker_id`);

--
-- Indexes for table `gebruiker`
--
ALTER TABLE `gebruiker`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `emailadres` (`emailadres`);

--
-- Indexes for table `machine`
--
ALTER TABLE `machine`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `ticket`
--
ALTER TABLE `ticket`
  ADD PRIMARY KEY (`id`),
  ADD KEY `gebruiker_id` (`gebruiker_id`);

--
-- Indexes for table `verkocht`
--
ALTER TABLE `verkocht`
  ADD PRIMARY KEY (`id`),
  ADD KEY `machine_id` (`machine_id`),
  ADD KEY `gebruiker_id` (`gebruiker_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `contract`
--
ALTER TABLE `contract`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `gebruiker`
--
ALTER TABLE `gebruiker`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `machine`
--
ALTER TABLE `machine`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `ticket`
--
ALTER TABLE `ticket`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `verkocht`
--
ALTER TABLE `verkocht`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `contract`
--
ALTER TABLE `contract`
  ADD CONSTRAINT `contract_ibfk_1` FOREIGN KEY (`gebruiker_id`) REFERENCES `gebruiker` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `ticket`
--
ALTER TABLE `ticket`
  ADD CONSTRAINT `ticket_ibfk_1` FOREIGN KEY (`gebruiker_id`) REFERENCES `gebruiker` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `verkocht`
--
ALTER TABLE `verkocht`
  ADD CONSTRAINT `verkocht_ibfk_1` FOREIGN KEY (`machine_id`) REFERENCES `machine` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `verkocht_ibfk_2` FOREIGN KEY (`gebruiker_id`) REFERENCES `gebruiker` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
