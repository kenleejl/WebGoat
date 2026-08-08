/*
 * SPDX-FileCopyrightText: Copyright © 2020 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.pathtraversal;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import lombok.Getter;
import lombok.SneakyThrows;
import org.apache.commons.io.FilenameUtils;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Getter
public class ProfileUploadBase implements AssignmentEndpoint {

  private static final long MAX_IMAGE_SIZE = 5 * 1024 * 1024;
  private final String webGoatHomeDirectory;

  public ProfileUploadBase(String webGoatHomeDirectory) {
    this.webGoatHomeDirectory = webGoatHomeDirectory;
  }

  protected AttackResult execute(MultipartFile file, String fullName, String username) {
    if (file.isEmpty()) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }
    if (StringUtils.isEmpty(fullName)) {
      return failed(this).feedback("path-traversal-profile-empty-name").build();
    }
    if (file.getSize() > MAX_IMAGE_SIZE) {
      return failed(this).feedback("path-traversal-profile-empty-file").build();
    }

    File uploadDirectory = cleanupAndCreateDirectoryForUser(username);

    try {
      byte[] image = file.getBytes();
      String extension = imageExtension(image);
      if (extension == null) {
        return failed(this).feedback("path-traversal-profile-empty-file").build();
      }

      var uploadRoot = uploadDirectory.toPath().toAbsolutePath().normalize();
      var uploadedFile = uploadRoot.resolve("profile." + extension).normalize();
      if (!uploadedFile.startsWith(uploadRoot)) {
        return failed(this).build();
      }
      Files.write(
          uploadedFile,
          image,
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
          StandardOpenOption.WRITE);
      return informationMessage(this)
          .feedback("path-traversal-profile-updated")
          .feedbackArgs(uploadedFile.getFileName())
          .build();

    } catch (IOException e) {
      return failed(this).output(e.getMessage()).build();
    }
  }

  @SneakyThrows
  protected File cleanupAndCreateDirectoryForUser(String username) {
    var safeUsername = username.replaceAll("[^A-Za-z0-9._-]", "_");
    if (safeUsername.isBlank()) {
      throw new IllegalArgumentException("Invalid username");
    }
    var uploadDirectory = new File(this.webGoatHomeDirectory, "PathTraversal/" + safeUsername);
    Files.createDirectories(uploadDirectory.toPath());
    return uploadDirectory;
  }

  private String imageExtension(byte[] image) {
    if (image.length >= 3
        && (image[0] & 0xff) == 0xff
        && (image[1] & 0xff) == 0xd8
        && (image[2] & 0xff) == 0xff) {
      return "jpg";
    }
    byte[] pngSignature = {(byte) 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a};
    if (image.length >= pngSignature.length
        && Arrays.equals(Arrays.copyOf(image, pngSignature.length), pngSignature)) {
      return "png";
    }
    return null;
  }

  public ResponseEntity<?> getProfilePicture(@CurrentUsername String username) {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType(MediaType.IMAGE_JPEG_VALUE))
        .body(getProfilePictureAsBase64(username));
  }

  protected byte[] getProfilePictureAsBase64(String username) {
    var safeUsername = username.replaceAll("[^A-Za-z0-9._-]", "_");
    var profilePictureDirectory =
        new File(this.webGoatHomeDirectory, "PathTraversal/" + safeUsername);
    var profileDirectoryFiles = profilePictureDirectory.listFiles();

    if (profileDirectoryFiles != null && profileDirectoryFiles.length > 0) {
      return Arrays.stream(profileDirectoryFiles)
          .filter(file -> FilenameUtils.isExtension(file.getName(), List.of("jpg", "png")))
          .findFirst()
          .map(
              file -> {
                try (var inputStream = new FileInputStream(file)) {
                  return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
                } catch (IOException e) {
                  return defaultImage();
                }
              })
          .orElse(defaultImage());
    } else {
      return defaultImage();
    }
  }

  @SneakyThrows
  protected byte[] defaultImage() {
    var inputStream = getClass().getResourceAsStream("/images/account.png");
    return Base64.getEncoder().encode(FileCopyUtils.copyToByteArray(inputStream));
  }
}
