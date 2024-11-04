from os import listdir, getcwd
import pygame

def import_folder(path):
    surface_list = []

    
    for image in listdir(path):
        full_path = path + '/' + image
        image_surf = pygame.image.load(full_path).convert_alpha()
        surface_list.append(image_surf)

    return surface_list
